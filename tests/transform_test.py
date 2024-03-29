import oval.oval_transform as oval
import pandas as pd


def unit_test_definitions( advisories, rl_version ) :
    
    return oval.definitions( advisories, rl_version )


def unit_test_generate( definitions, rl_version ) :

    return oval.generate( definitions, rl_version )


def unit_test( rl_version ) :

    advisory = {
        'type': 'TYPE_SECURITY', 
        'shortCode': 'RL', 
        'name': 'RLSA-2022:7070', 
        'synopsis': 'Important: firefox security update', 
        'severity': 'SEVERITY_IMPORTANT', 
        'topic': 'An update for firefox is now available for Rocky Linux 8.\nRocky Enterprise Software Foundation Product Security has rated this update as having a security impact of Important. A Common Vulnerability Scoring System (CVSS) base score, which gives a detailed severity rating, is available for each vulnerability from the CVE link(s) in the References section.', 
        'description': 'Mozilla Firefox is an open-source web browser, designed for standards compliance, performance, and portability.\nThis update upgrades Firefox to version 102.4.0 ESR.\nFor more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.', 
        'solution': None, 
        'affectedProducts': ['Rocky Linux 8'], 
        'fixes': 
        [
            {
                'ticket': '2136156', 
                'sourceBy': 'Red Hat', 
                'sourceLink': 'https://bugzilla.redhat.com/show_bug.cgi?id=2136156', 
                'description': 'CVE-2022-42927 Mozilla: Same-origin policy violation could have leaked cross-origin URLs'
            },
            {
                'ticket': '2136157', 
                'sourceBy': 'Red Hat', 
                'sourceLink': 'https://bugzilla.redhat.com/show_bug.cgi?id=2136157', 
                'description': 'CVE-2022-42928 Mozilla: Memory Corruption in JS Engine'
            }, 
            {
                'ticket': '2136158',
                'sourceBy': 'Red Hat', 
                'sourceLink': 'https://bugzilla.redhat.com/show_bug.cgi?id=2136158', 
                'description': 'CVE-2022-42929 Mozilla: Denial of Service via window.print'
            }, 
            {
                'ticket': '2136159', 
                'sourceBy': 'Red Hat', 
                'sourceLink': 'https://bugzilla.redhat.com/show_bug.cgi?id=2136159', 
                'description': 'CVE-2022-42932 Mozilla: Memory safety bugs fixed in Firefox 106 and Firefox ESR 102.4'
            }
        ], 
        'cves': 
        [
            {
                'name': 'CVE-2022-42927', 
                'sourceBy': 'Red Hat', 
                'sourceLink': 'https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2022-42927.json',
                'cvss3ScoringVector': 'CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H', 
                'cvss3BaseScore': '7.5', 
                'cwe': 'CWE-829'
            },
            {
                'name': 'CVE-2022-42928', 
                'sourceBy': 'Red Hat', 
                'sourceLink': 'https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2022-42928.json',
                'cvss3ScoringVector': 'CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H', 
                'cvss3BaseScore': '7.5', 
                'cwe': 'CWE-120'
            },
            {
                'name': 'CVE-2022-42929',
                'sourceBy': 'Red Hat',
                'sourceLink': 'https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2022-42929.json',
                'cvss3ScoringVector': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                'cvss3BaseScore': '6.1',
                'cwe': 'CWE-400'
            }, 
            {
                'name': 'CVE-2022-42932', 
                'sourceBy': 'Red Hat', 
                'sourceLink': 'https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2022-42932.json',
                'cvss3ScoringVector': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                'cvss3BaseScore': '6.1',
                'cwe': 'CWE-120'
            }
        ], 
        'references': 
        [
        ], 
        'publishedAt': '2022-11-01T05:28:36.231631Z', 
        'rpms': 
        {
            'Rocky Linux 8': 
            {
                'nvras': 
                [
                    'firefox-0:102.4.0-1.el8_6.aarch64.rpm', 
                    'firefox-0:102.4.0-1.el8_6.src.rpm', 
                    'firefox-0:102.4.0-1.el8_6.x86_64.rpm', 
                    'firefox-debuginfo-0:102.4.0-1.el8_6.aarch64.rpm', 
                    'firefox-debuginfo-0:102.4.0-1.el8_6.x86_64.rpm', 
                    'firefox-debugsource-0:102.4.0-1.el8_6.aarch64.rpm', 
                    'firefox-debugsource-0:102.4.0-1.el8_6.x86_64.rpm'
                ]
            }
        }, 
        'rebootSuggested': False
    }

    advisories = pd.json_normalize( advisory )

    definitions = unit_test_definitions( advisories, rl_version )
    trfm = str( definitions )

    tests, objects, states = unit_test_generate( definitions, rl_version )
    trfm = trfm + str( tests )
    trfm = trfm + str( objects )
    trfm = trfm + str( states )

    return trfm

    
def main( ):

    rl_version = 8
    print( unit_test( rl_version ) )


if __name__ == "__main__":
    main()
