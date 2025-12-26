import psycopg2
import xml.etree.ElementTree as ET
import json
from pathlib import Path

#cwe_node:CWE 编号、层级关系、CWE 名称、官方状态、官方简要描述、扩展描述、利用可能性、关联弱点列表、弱点序性、适用平台、背景细节、备用术语、引入方式、利用因子、常见后果、检测方法、缓解措施、
#         观测案例、功能领域、受影响资源、分类映射、相关攻击模式、 备注、 数据版本：4.18
#cwe_relation：CWE 编号、 视图 ID：1000、关系类型、目标 CWE编号、数据版本：4.18
#用于rag字段：CWE 编号、层级关系、CWE 名称、官方简要描述、扩展描述、常见后果、观测案例

# ================== 配置 ===================
NS = {
    'cwe': 'http://cwe.mitre.org/cwe-7',
    'xhtml': 'http://www.w3.org/1999/xhtml'
}

_ZERO_WIDTH = "\u200b\u200c\u200d\ufeff\u00ad"

# ================== 数据库 ===================
def connect_pg():
    conn = psycopg2.connect(
        dbname="rag-type",
        user="postgres",
        password="123456",
        host="localhost",
        port="5432"
    )
    conn.autocommit = False
    return conn

# ================== 文本规范化 ===================
def normalize_text(value: str) -> str:
    """清理字符串中的零宽字符与多余空白"""
    if value is None:
        return ''
    s = str(value)
    for ch in _ZERO_WIDTH:
        s = s.replace(ch, '')
    s = s.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ').replace('\xa0', ' ')
    s = ' '.join(s.split())
    return s.strip()

def normalize_structure(obj):
    """递归清理字符串、列表、字典"""
    if isinstance(obj, str):
        return normalize_text(obj)
    if isinstance(obj, list):
        return [normalize_structure(x) for x in obj]
    if isinstance(obj, dict):
        return {k: normalize_structure(v) for k, v in obj.items()}
    return obj

# ================== 建表 ===================
def create_tables(cur):
    """删除旧表并创建 cwe_node / cwe_relation"""
    cur.execute('''
        DROP TABLE IF EXISTS cwe_relation;
        DROP TABLE IF EXISTS cwe_node;
    ''')

    # cwe_node
    cur.execute('''
        CREATE TABLE cwe_node (
            cweId INTEGER PRIMARY KEY,
            patch TEXT DEFAULT '',
            nameEn TEXT NOT NULL,
            status TEXT DEFAULT '',
            description TEXT DEFAULT '',
            extendedDescription TEXT DEFAULT '',
            likelihoodOfExp TEXT DEFAULT '',
            relatedWeaknesses TEXT DEFAULT '',
            weaknessOrdinalities TEXT DEFAULT '',
            applicablePlatforms TEXT DEFAULT '',
            backgroundDetails TEXT DEFAULT '',
            alternateTerms TEXT DEFAULT '',
            modesOfIntroduction TEXT DEFAULT '',
            exploitationFactors TEXT DEFAULT '',
            commonConsequences TEXT DEFAULT '',
            detectionMethods TEXT DEFAULT '',
            potentialMitigations TEXT DEFAULT '',
            observedExamples TEXT DEFAULT '',
            functionalAreas TEXT DEFAULT '',
            affectedResources TEXT DEFAULT '',
            taxonomyMappings TEXT DEFAULT '',
            relatedAttackPatterns TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            version TEXT NOT NULL
        );
        CREATE INDEX cwe_node_ind ON cwe_node (cweId);
    ''')

    # cwe_relation
    cur.execute('''
        CREATE TABLE cwe_relation (
            cwe_relation_id SERIAL PRIMARY KEY,
            cweId INTEGER NOT NULL,
            viewId INTEGER NOT NULL,
            relation TEXT NOT NULL,
            targetCweId INTEGER NOT NULL,
            ordinal TEXT DEFAULT '',
            version TEXT NOT NULL
        );
        CREATE INDEX cwe_relation_ind ON cwe_relation (viewId, cweId, targetCweId, relation);
    ''')


def upsert_cwe_node(cur, values):
    """插入或更新 CWE 节点信息"""
    def _clean(v):
        return None if isinstance(v, str) and not v.strip() else v

    values = tuple(_clean(v) for v in values)
    cur.execute('''
        INSERT INTO cwe_node (
            cweId, patch, nameEn, status, description, extendedDescription, likelihoodOfExp,
            relatedWeaknesses, weaknessOrdinalities, applicablePlatforms, backgroundDetails,
            alternateTerms, modesOfIntroduction, exploitationFactors, commonConsequences,
            detectionMethods, potentialMitigations, observedExamples, functionalAreas,
            affectedResources, taxonomyMappings, relatedAttackPatterns, notes, version
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (cweId) DO UPDATE SET
          patch = EXCLUDED.patch,
          nameEn = EXCLUDED.nameEn,
          status = EXCLUDED.status,
          description = EXCLUDED.description,
          extendedDescription = EXCLUDED.extendedDescription,
          likelihoodOfExp = EXCLUDED.likelihoodOfExp,
          relatedWeaknesses = EXCLUDED.relatedWeaknesses,
          weaknessOrdinalities = EXCLUDED.weaknessOrdinalities,
          applicablePlatforms = EXCLUDED.applicablePlatforms,
          backgroundDetails = EXCLUDED.backgroundDetails,
          alternateTerms = EXCLUDED.alternateTerms,
          modesOfIntroduction = EXCLUDED.modesOfIntroduction,
          exploitationFactors = EXCLUDED.exploitationFactors,
          commonConsequences = EXCLUDED.commonConsequences,
          detectionMethods = EXCLUDED.detectionMethods,
          potentialMitigations = EXCLUDED.potentialMitigations,
          observedExamples = EXCLUDED.observedExamples,
          functionalAreas = EXCLUDED.functionalAreas,
          affectedResources = EXCLUDED.affectedResources,
          taxonomyMappings = EXCLUDED.taxonomyMappings,
          relatedAttackPatterns = EXCLUDED.relatedAttackPatterns,
          notes = EXCLUDED.notes,
          version = EXCLUDED.version;
    ''', values)


def insert_relation(cur, cwe_id, view_id, relation, target_cwe_id, version):
    """插入 CWE 关系记录"""
    cur.execute('''
        INSERT INTO cwe_relation (cweId, viewId, relation, targetCweId, version)
        VALUES (%s,%s,%s,%s,%s)
    ''', (cwe_id, view_id, relation, target_cwe_id, version))


# ================== 解析xml ===================
def parse_and_load(xml_path, conn):
    """解析 CWE XML 文件并写入数据库"""
    cur = conn.cursor()
    tree = ET.parse(xml_path)
    root = tree.getroot()
    version = root.get('Version', '1.0')

    # Weaknesses
    for weakness in root.findall('cwe:Weaknesses/cwe:Weakness', NS):
        cwe_id = int(weakness.get('ID'))
        name = normalize_text(weakness.get('Name', ''))
        status = normalize_text(weakness.get('Status', ''))
        description = ''
        extended_description = ''
        likelihood = ''

        desc_elem = weakness.find('cwe:Description', NS)
        if desc_elem is not None:
            description = normalize_text(desc_elem.text or '')

        extended_elem = weakness.find('cwe:Extended_Description', NS)
        if extended_elem is not None:
            extended_description = normalize_text(extended_elem.text or '')

        likelihood_elem = weakness.find('cwe:Likelihood_Of_Exploit', NS)
        if likelihood_elem is not None:
            likelihood = normalize_text(likelihood_elem.text or '')

        # 构建多字段 JSON
        related_json = '[]'
        related = weakness.find('cwe:Related_Weaknesses', NS)
        if related is not None:
            rels = []
            for rel in related.findall('cwe:Related_Weakness', NS):
                rels.append(normalize_structure({
                    'Nature': rel.get('Nature', ''),
                    'CWE_ID': rel.get('CWE_ID', ''),
                    'View_ID': rel.get('View_ID', ''),
                    'Ordinal': rel.get('Ordinal', '')
                }))
            related_json = json.dumps(rels, ensure_ascii=False)

        ordinalities_json = '[]'
        ords = []
        for ord_elem in weakness.findall('cwe:Weakness_Ordinalities/cwe:Weakness_Ordinality', NS):
            parts = []
            for child in list(ord_elem):
                if child.text and child.text.strip():
                    parts.append(normalize_text(child.text))
            if parts:
                ords.append(' | '.join(parts))
        if ords:
            ordinalities_json = json.dumps(ords, ensure_ascii=False)

        platforms_json = '[]'
        platforms = []
        for p in weakness.findall('cwe:Applicable_Platforms/*', NS):
            tag = p.tag.split('}')[-1]
            entry = {'type': tag}
            entry.update({k: v for k, v in p.attrib.items()})
            text = normalize_text(p.text or '')
            if text:
                entry['text'] = text
            platforms.append(normalize_structure(entry))
        if platforms:
            platforms_json = json.dumps(platforms, ensure_ascii=False)

        background_json = '[]'
        backs = []
        for b in weakness.findall('cwe:Background_Details/cwe:Background_Detail', NS):
            txt = normalize_text(b.text or '')
            if txt:
                backs.append(txt)
        if backs:
            background_json = json.dumps(backs, ensure_ascii=False)

        alternate_json = '[]'
        alts = []
        for a in weakness.findall('cwe:Alternate_Terms/cwe:Alternate_Term', NS):
            vals = []
            for child in list(a):
                if child.text and normalize_text(child.text):
                    vals.append(normalize_text(child.text))
            if vals:
                alts.append(' | '.join(vals))
        if alts:
            alternate_json = json.dumps(alts, ensure_ascii=False)

        modes_json = '[]'
        modes = []
        for intro in weakness.findall('cwe:Modes_Of_Introduction/cwe:Introduction', NS):
            rec = {}
            for child in list(intro):
                key = child.tag.split('}')[-1]
                val = normalize_text(child.text or '')
                if val:
                    rec[key] = val
            if rec:
                modes.append(normalize_structure(rec))
        if modes:
            modes_json = json.dumps(modes, ensure_ascii=False)

        consequences_json = '[]'
        cons = []
        for c in weakness.findall('cwe:Common_Consequences/cwe:Consequence', NS):
            rec = {}
            for child in list(c):
                key = child.tag.split('}')[-1]
                val = normalize_text(child.text or '')
                if val:
                    if key in rec:
                        if isinstance(rec[key], list):
                            rec[key].append(val)
                        else:
                            rec[key] = [rec[key], val]
                    else:
                        rec[key] = val
            if rec:
                cons.append(normalize_structure(rec))
        if cons:
            consequences_json = json.dumps(cons, ensure_ascii=False)

        detection_json = '[]'
        dets = []
        for d in weakness.findall('cwe:Detection_Methods/cwe:Detection_Method', NS):
            rec = {}
            for child in list(d):
                key = child.tag.split('}')[-1]
                val = normalize_text(child.text or '')
                if val:
                    rec[key] = val
            if rec:
                dets.append(normalize_structure(rec))
        if dets:
            detection_json = json.dumps(dets, ensure_ascii=False)

        mitigations_json = '[]'
        mits = []
        for m in weakness.findall('cwe:Potential_Mitigations/cwe:Mitigation', NS):
            rec = {}
            for child in list(m):
                key = child.tag.split('}')[-1]
                val = normalize_text(child.text or '')
                if val:
                    rec[key] = val
            if rec:
                mits.append(normalize_structure(rec))
        if mits:
            mitigations_json = json.dumps(mits, ensure_ascii=False)

        observed_json = '[]'
        obs = []
        for o in weakness.findall('cwe:Observed_Examples/cwe:Observed_Example', NS):
            rec = {}
            for child in list(o):
                key = child.tag.split('}')[-1]
                val = normalize_text(child.text or '')
                if val:
                    rec[key] = val
            if rec:
                obs.append(normalize_structure(rec))
        if obs:
            observed_json = json.dumps(obs, ensure_ascii=False)

        functional_json = '[]'
        funcs = []
        for f in weakness.findall('cwe:Functional_Areas/cwe:Functional_Area', NS):
            txt = normalize_text(f.text or '')
            if txt:
                funcs.append(txt)
        if funcs:
            functional_json = json.dumps(funcs, ensure_ascii=False)

        affected_json = '[]'
        affs = []
        for ar in weakness.findall('cwe:Affected_Resources/cwe:Affected_Resource', NS):
            txt = normalize_text(ar.text or '')
            if txt:
                affs.append(txt)
        if affs:
            affected_json = json.dumps(affs, ensure_ascii=False)

        taxonomy_json = '[]'
        taxes = []
        for tm in weakness.findall('cwe:Taxonomy_Mappings/cwe:Taxonomy_Mapping', NS):
            rec = {k: v for k, v in tm.attrib.items()}
            for child in list(tm):
                key = child.tag.split('}')[-1]
                val = normalize_text(child.text or '')
                if val:
                    rec[key] = val
            if rec:
                taxes.append(normalize_structure(rec))
        if taxes:
            taxonomy_json = json.dumps(taxes, ensure_ascii=False)

        capecs = []
        for rp in weakness.findall('cwe:Related_Attack_Patterns/cwe:Related_Attack_Pattern', NS):
            cid = rp.get('CAPEC_ID')
            if cid:
                capecs.append(cid)
        if capecs:
            capec_json = json.dumps(capecs, ensure_ascii=False)
        else:
            capec_json = '[]'

        notes_json = '[]'
        notes = []
        for n in weakness.findall('cwe:Notes/cwe:Note', NS):
            rec = {'Type': n.get('Type', '')}
            txt = normalize_text(n.text or '')
            if txt:
                rec['Text'] = txt
            notes.append(normalize_structure(rec))
        if notes:
            notes_json = json.dumps(notes, ensure_ascii=False)

        upsert_cwe_node(cur, (
            cwe_id, '', name, status, description, extended_description, likelihood,
            related_json, ordinalities_json, platforms_json, background_json,
            alternate_json, modes_json, '[]', consequences_json, detection_json,
            mitigations_json, observed_json, functional_json, affected_json,
            taxonomy_json, capec_json, notes_json, version
        ))

        related = weakness.find('cwe:Related_Weaknesses', NS)
        if related is not None:
            for rel in related.findall('cwe:Related_Weakness', NS):
                if rel.get('Nature') == 'ChildOf':
                    parent_id = int(rel.get('CWE_ID'))
                    rel_view_id = int(rel.get('View_ID', '1000'))
                    insert_relation(cur, parent_id, rel_view_id, 'ChildOf', cwe_id, version)

    # Categories
    for category in root.findall('cwe:Categories/cwe:Category', NS):
        cwe_id = int(category.get('ID'))
        name = category.get('Name', '')
        status = category.get('Status', '')
        description = ''
        desc_elem = category.find('cwe:Description', NS)
        if desc_elem is not None:
            description = desc_elem.text or ''

        upsert_cwe_node(cur, (
            cwe_id, '', name, status, description, '', '',
            '[]','[]','[]','[]','[]','[]','[]','[]','[]','[]','[]','[]','[]','[]','[]','[]', version
        ))

        relations = category.find('cwe:Relationships', NS)
        if relations is not None:
            for rel in relations.findall('cwe:Has_Member', NS):
                target_id = int(rel.get('CWE_ID'))
                rel_view_id = int(rel.get('View_ID', '1000'))
                insert_relation(cur, cwe_id, rel_view_id, 'ChildOf', target_id, version)

    # Views
    for view in root.findall('cwe:Views/cwe:View', NS):
        cwe_id = int(view.get('ID'))
        name = view.get('Name', '')
        status = view.get('Status', '')
        description = ''
        desc_elem = view.find('cwe:Description', NS)
        if desc_elem is not None:
            description = desc_elem.text or ''

        upsert_cwe_node(cur, (
            cwe_id, '', name, status, description, '', '',
            '[]','[]','[]','[]','[]','[]','[]','[]','[]','[]','[]','[]','[]','[]','[]','[]', version
        ))

        members = view.find('cwe:Members', NS)
        if members is not None:
            for rel in members.findall('cwe:Has_Member', NS):
                target_id = int(rel.get('CWE_ID'))
                rel_view_id = int(rel.get('View_ID', str(cwe_id)))
                insert_relation(cur, cwe_id, rel_view_id, 'ChildOf', target_id, version)

    conn.commit()

# ================== 层级链路 ===================
def compute_and_update_patch(conn, view_id: int = 1000) -> None:
    """计算并更新每个节点的 CWE 层级路径"""
    cur = conn.cursor()
    cur.execute('SELECT cweId FROM cwe_node ORDER BY cweId')
    ids = [row[0] for row in cur.fetchall()]

    sql = (
        """
        WITH RECURSIVE tc(level, targetCweId, path) AS (
            SELECT 0 AS level,
                   r.targetCweId,
                   (r.targetCweId)::text AS path
            FROM cwe_relation r
            WHERE r.viewId = %s AND r.cweId = %s AND r.relation = 'ChildOf'
            UNION ALL
            SELECT tc.level + 1,
                   r.targetCweId,
                   tc.path || '->' || (r.targetCweId)::text AS path
            FROM cwe_relation r
            JOIN tc ON r.cweId = tc.targetCweId
            WHERE r.viewId = %s AND r.relation = 'ChildOf'
        )
        SELECT level, targetCweId, path
        FROM tc
        WHERE tc.targetCweId = %s
        ORDER BY level, path;
        """
    )

    for cid in ids:
        cur.execute(sql, (view_id, view_id, view_id, cid))
        rows = cur.fetchall()
        seen = set()
        paths = []
        for r in rows:
            if r and len(r) >= 3 and r[2]:
                p = r[2]
                if p not in seen:
                    seen.add(p)
                    paths.append(p)
        if not paths:
            paths = [str(cid)]
        cur.execute('UPDATE cwe_node SET patch = %s WHERE cweId = %s', (json.dumps(paths, ensure_ascii=False), cid))
    conn.commit()

# ================== 主程序 ===================
def main():
    xml_file = 'datasets1/1000.xml'
    conn = connect_pg()
    try:
        cur = conn.cursor()
        create_tables(cur)
        conn.commit()
        parse_and_load(xml_file, conn)
        compute_and_update_patch(conn, view_id=1000)
        cur.execute('SELECT COUNT(*) FROM cwe_node')
        print('节点数量:', cur.fetchone()[0])
        cur.execute('SELECT COUNT(*) FROM cwe_relation')
        print('关系数量:', cur.fetchone()[0])
    finally:
        conn.close()


if __name__ == '__main__':
    main()


