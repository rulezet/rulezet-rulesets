rule rule_wfuzz_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wfuzz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wfuzz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_wfuzz_offensive_tool_keyword = /\sadmin\-panels\.txt/
                        $string2_wfuzz_offensive_tool_keyword = /\sAll_attack\.txt/
                        $string3_wfuzz_offensive_tool_keyword = /\s\-c\s\-w\smethods\.txt\s\-p\s127\.0\.0\.1/
                        $string4_wfuzz_offensive_tool_keyword = /\s\-c\s\-z\srange.{0,1000}1\-10\s\-\-hc\=BBB\shttp/
                        $string5_wfuzz_offensive_tool_keyword = /\scommon_pass\.txt/
                        $string6_wfuzz_offensive_tool_keyword = " FUZZ:FUZZ "
                        $string7_wfuzz_offensive_tool_keyword = " install wfuzz"
                        $string8_wfuzz_offensive_tool_keyword = " -u FUZZ "
                        $string9_wfuzz_offensive_tool_keyword = /\s\-w\swordlist\/.{0,1000}\.txt.{0,1000}http/
                        $string10_wfuzz_offensive_tool_keyword = /\sws\-dirs\.txt/
                        $string11_wfuzz_offensive_tool_keyword = /\sws\-files\.txt/
                        $string12_wfuzz_offensive_tool_keyword = " -X FUZZ http"
                        $string13_wfuzz_offensive_tool_keyword = " -z burplog"
                        $string14_wfuzz_offensive_tool_keyword = /\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd/
                        $string15_wfuzz_offensive_tool_keyword = /\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/shadow/
                        $string16_wfuzz_offensive_tool_keyword = /\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/boot\.ini/
                        $string17_wfuzz_offensive_tool_keyword = /\/admin\-panels\.txt/
                        $string18_wfuzz_offensive_tool_keyword = /\/All_attack\.txt/
                        $string19_wfuzz_offensive_tool_keyword = /\/Injections\/SQL\.txt/
                        $string20_wfuzz_offensive_tool_keyword = /\/sql_inj\.txt/
                        $string21_wfuzz_offensive_tool_keyword = "/wfuzz "
                        $string22_wfuzz_offensive_tool_keyword = /\/ws\-dirs\.txt/
                        $string23_wfuzz_offensive_tool_keyword = /\/ws\-files\.txt/
                        $string24_wfuzz_offensive_tool_keyword = /\\admin\-panels\.txt/
                        $string25_wfuzz_offensive_tool_keyword = /\\All_attack\.txt/
                        $string26_wfuzz_offensive_tool_keyword = /\\common_pass\.txt/
                        $string27_wfuzz_offensive_tool_keyword = /\\ws\-dirs\.txt/
                        $string28_wfuzz_offensive_tool_keyword = /\\ws\-files\.txt/
                        $string29_wfuzz_offensive_tool_keyword = /buffer_overflow\.py/
                        $string30_wfuzz_offensive_tool_keyword = /burp_log_.{0,1000}\.log/
                        $string31_wfuzz_offensive_tool_keyword = /burpitem\.py/
                        $string32_wfuzz_offensive_tool_keyword = /burplog\.py/
                        $string33_wfuzz_offensive_tool_keyword = /burpstate\.py/
                        $string34_wfuzz_offensive_tool_keyword = /dirTraversal\.txt/
                        $string35_wfuzz_offensive_tool_keyword = /dirTraversal\-nix\.txt/
                        $string36_wfuzz_offensive_tool_keyword = /dirTraversal\-win\.txt/
                        $string37_wfuzz_offensive_tool_keyword = /dirwalk\.py/
                        $string38_wfuzz_offensive_tool_keyword = /from\s\.core\simport\sFuzzer/
                        $string39_wfuzz_offensive_tool_keyword = /from\s\.wfuzz\simport\s/
                        $string40_wfuzz_offensive_tool_keyword = /fuzzfactory\.py/
                        $string41_wfuzz_offensive_tool_keyword = /fuzzrequest\.py/
                        $string42_wfuzz_offensive_tool_keyword = /http\:\/\/127\.0\.0\.1\/FUZZ/
                        $string43_wfuzz_offensive_tool_keyword = /http\:\/\/wfuzz\.org/
                        $string44_wfuzz_offensive_tool_keyword = /https\:\/\/wfuzz\.readthedocs\.io/
                        $string45_wfuzz_offensive_tool_keyword = "import wfuzz"
                        $string46_wfuzz_offensive_tool_keyword = /Injections\/Traversal\.txt/
                        $string47_wfuzz_offensive_tool_keyword = /Injections\/XSS\.txt/
                        $string48_wfuzz_offensive_tool_keyword = /shodanp\.py/
                        $string49_wfuzz_offensive_tool_keyword = "site-packages/wfuzz"
                        $string50_wfuzz_offensive_tool_keyword = /subdomains\-top1million\-20000\.txt/
                        $string51_wfuzz_offensive_tool_keyword = "uname=FUZZ&pass=FUZZ"
                        $string52_wfuzz_offensive_tool_keyword = /vulns\/apache\.txt/
                        $string53_wfuzz_offensive_tool_keyword = /vulns\/iis\.txt/
                        $string54_wfuzz_offensive_tool_keyword = /vulns\/jrun\.txt/
                        $string55_wfuzz_offensive_tool_keyword = /vulns\/tomcat\.txt/
                        $string56_wfuzz_offensive_tool_keyword = /vulnweb\.com\/FUZZ/
                        $string57_wfuzz_offensive_tool_keyword = "wfencode -"
                        $string58_wfuzz_offensive_tool_keyword = "wfencode -e "
                        $string59_wfuzz_offensive_tool_keyword = /wfencode\.bat/
                        $string60_wfuzz_offensive_tool_keyword = /wfencode\.py/
                        $string61_wfuzz_offensive_tool_keyword = "wfpayload -"
                        $string62_wfuzz_offensive_tool_keyword = /wfpayload\.bat/
                        $string63_wfuzz_offensive_tool_keyword = /wfpayload\.py/
                        $string64_wfuzz_offensive_tool_keyword = /wfuzz\.bat/
                        $string65_wfuzz_offensive_tool_keyword = /wfuzz\.get_payload/
                        $string66_wfuzz_offensive_tool_keyword = /wfuzz\.py/
                        $string67_wfuzz_offensive_tool_keyword = /wfuzz\.wfuzz/
                        $string68_wfuzz_offensive_tool_keyword = /wfuzz\-cli\.py/
                        $string69_wfuzz_offensive_tool_keyword = /wfuzzp\.py/
                        $string70_wfuzz_offensive_tool_keyword = /www\.wfuzz\.org/
                        $string71_wfuzz_offensive_tool_keyword = /wxfuzz\.bat/
                        $string72_wfuzz_offensive_tool_keyword = /wxfuzz\.py/
                        $string73_wfuzz_offensive_tool_keyword = "xmendez/wfuzz"

    condition:
        any of them
}