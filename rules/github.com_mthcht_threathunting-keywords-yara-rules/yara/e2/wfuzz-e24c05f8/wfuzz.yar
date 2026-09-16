rule wfuzz
{
    meta:
        description = "Detection patterns for the tool 'wfuzz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wfuzz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sadmin\-panels\.txt/
                        $string2 = /\sAll_attack\.txt/
                        $string3 = /\s\-c\s\-w\smethods\.txt\s\-p\s127\.0\.0\.1/
                        $string4 = /\s\-c\s\-z\srange.{0,1000}1\-10\s\-\-hc\=BBB\shttp/
                        $string5 = /\scommon_pass\.txt/
                        $string6 = " FUZZ:FUZZ "
                        $string7 = " install wfuzz"
                        $string8 = " -u FUZZ "
                        $string9 = /\s\-w\swordlist\/.{0,1000}\.txt.{0,1000}http/
                        $string10 = /\sws\-dirs\.txt/
                        $string11 = /\sws\-files\.txt/
                        $string12 = " -X FUZZ http"
                        $string13 = " -z burplog"
                        $string14 = /\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/passwd/
                        $string15 = /\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/etc\/shadow/
                        $string16 = /\/\.\.\/\.\.\/\.\.\/\.\.\/\.\.\/boot\.ini/
                        $string17 = /\/admin\-panels\.txt/
                        $string18 = /\/All_attack\.txt/
                        $string19 = /\/Injections\/SQL\.txt/
                        $string20 = /\/sql_inj\.txt/
                        $string21 = "/wfuzz "
                        $string22 = /\/ws\-dirs\.txt/
                        $string23 = /\/ws\-files\.txt/
                        $string24 = /\\admin\-panels\.txt/
                        $string25 = /\\All_attack\.txt/
                        $string26 = /\\common_pass\.txt/
                        $string27 = /\\ws\-dirs\.txt/
                        $string28 = /\\ws\-files\.txt/
                        $string29 = /buffer_overflow\.py/
                        $string30 = /burp_log_.{0,1000}\.log/
                        $string31 = /burpitem\.py/
                        $string32 = /burplog\.py/
                        $string33 = /burpstate\.py/
                        $string34 = /dirTraversal\.txt/
                        $string35 = /dirTraversal\-nix\.txt/
                        $string36 = /dirTraversal\-win\.txt/
                        $string37 = /dirwalk\.py/
                        $string38 = /from\s\.core\simport\sFuzzer/
                        $string39 = /from\s\.wfuzz\simport\s/
                        $string40 = /fuzzfactory\.py/
                        $string41 = /fuzzrequest\.py/
                        $string42 = /http\:\/\/127\.0\.0\.1\/FUZZ/
                        $string43 = /http\:\/\/wfuzz\.org/
                        $string44 = /https\:\/\/wfuzz\.readthedocs\.io/
                        $string45 = "import wfuzz"
                        $string46 = /Injections\/Traversal\.txt/
                        $string47 = /Injections\/XSS\.txt/
                        $string48 = /shodanp\.py/
                        $string49 = "site-packages/wfuzz"
                        $string50 = /subdomains\-top1million\-20000\.txt/
                        $string51 = "uname=FUZZ&pass=FUZZ"
                        $string52 = /vulns\/apache\.txt/
                        $string53 = /vulns\/iis\.txt/
                        $string54 = /vulns\/jrun\.txt/
                        $string55 = /vulns\/tomcat\.txt/
                        $string56 = /vulnweb\.com\/FUZZ/
                        $string57 = "wfencode -"
                        $string58 = "wfencode -e "
                        $string59 = /wfencode\.bat/
                        $string60 = /wfencode\.py/
                        $string61 = "wfpayload -"
                        $string62 = /wfpayload\.bat/
                        $string63 = /wfpayload\.py/
                        $string64 = /wfuzz\.bat/
                        $string65 = /wfuzz\.get_payload/
                        $string66 = /wfuzz\.py/
                        $string67 = /wfuzz\.wfuzz/
                        $string68 = /wfuzz\-cli\.py/
                        $string69 = /wfuzzp\.py/
                        $string70 = /www\.wfuzz\.org/
                        $string71 = /wxfuzz\.bat/
                        $string72 = /wxfuzz\.py/
                        $string73 = "xmendez/wfuzz"

    condition:
        any of them
}