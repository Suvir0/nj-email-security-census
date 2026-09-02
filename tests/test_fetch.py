"""Directory parsing on a synthetic CSV shaped like the NJDOE download."""

import fetch_districts as fd

HEADER = ("County Code,County Name,District Code,District Name,Chrt Sch Code,Supt. Title,"
          "Supt. First Name,Supt. Last Name,Supt. Title 2,Supt. EMail,BA Email,Website,NCES ID")

PREAMBLE = "This worksheet includes one table.\r\nNew Jersey School Directory\r\nPublic School Districts\r\n"


def row(cc, cn, dc, name, supt_email, ba_email, website, nces="3400001"):
    return f'="{cc}",{cn},="{dc}",{name},,Dr.,Pat,Lee,,{supt_email},{ba_email},{website},="{nces}"'


SAMPLE = PREAMBLE + "\r\n".join([
    HEADER,
    row("01", "ATLANTIC", "0010", "Alpha Public Schools", "s@alphaschools.org", "b@alphaschools.org", "https://www.alphaschools.org/"),
    row("03", "BERGEN", "0020", "Beta School District", "s@nvnet.org", "b@nvnet.org", "www.betaschools.org"),
    row("03", "BERGEN", "0030", "Gamma School District", "s@nvnet.org", "", "WWW.GAMMA.K12.NJ.US/domain/5"),
    row("05", "BURLINGTON", "0040", "Delta Board of Education", "s@gmail.com", "b@gmail.com", "none"),
    row("80", "CAMDEN", "6000", "Epsilon Charter School", "", "b@epsiloncs.org", "sites.google.com/epsiloncs.org/home"),
    row("07", "CAMDEN", "0050", "Zeta County Vocational School District", "s@zetatech.org", "b@zetatech.org", "Rose"),
    row("07", "CAMDEN", "0060", "Eta Township School District", "", "", "www.etaschools.org"),
    row("07", "CAMDEN", "0070", "Theta School District", "s@yahoo.com", "b@thetaschools.org", "n/a"),
    "",
]) + "\r\n"


def by_name(rows):
    return {r["district_name"]: r for r in rows}


def test_parse_directory_end_to_end():
    rows = fd.parse_directory(SAMPLE)
    assert len(rows) == 8
    r = by_name(rows)

    a = r["Alpha Public Schools"]
    assert a["county_code"] == "01" and a["district_code"] == "0010" and a["nces_id"] == "3400001"
    assert a["county_name"] == "Atlantic" and a["district_type"] == "regular"
    assert a["website_domain"] == "alphaschools.org" and a["email_domain"] == "alphaschools.org"
    assert a["assessed_domain"] == "alphaschools.org" and a["domain_source"] == "supt_email"
    assert not a["domain_mismatch"] and not a["shared_domain"]

    b, g = r["Beta School District"], r["Gamma School District"]
    assert b["assessed_domain"] == g["assessed_domain"] == "nvnet.org"
    assert b["domain_mismatch"] and b["shared_domain"] and b["shared_with_count"] == 1
    assert g["website_domain"] == "gamma.k12.nj.us"  # PSL: k12.nj.us is a public suffix

    d = r["Delta Board of Education"]
    assert d["assessed_domain"] == "gmail.com" and d["domain_flag"] == "consumer_provider"
    assert d["website_domain"] == "" and d["website_flag"] == "missing"

    e = r["Epsilon Charter School"]
    assert e["district_type"] == "charter"
    assert e["website_flag"] == "third_party_host" and e["website_domain"] == ""
    assert e["assessed_domain"] == "epsiloncs.org" and e["domain_source"] == "ba_email"

    z = r["Zeta County Vocational School District"]
    assert z["district_type"] == "vocational" and z["website_flag"] == "junk_value"

    eta = r["Eta Township School District"]
    assert eta["assessed_domain"] == "etaschools.org" and eta["domain_source"] == "website"

    th = r["Theta School District"]
    assert th["assessed_domain"] == "thetaschools.org" and th["domain_source"] == "ba_email"


def test_no_email_addresses_leak_into_output():
    rows = fd.parse_directory(SAMPLE)
    for r in rows:
        for v in r.values():
            assert "@" not in str(v)
    assert set(rows[0]) == set(fd.OUTPUT_COLUMNS)


def test_unwrap_excel():
    assert fd.unwrap_excel('="01"') == "01"
    assert fd.unwrap_excel("01") == "01"
    assert fd.unwrap_excel("") == ""
