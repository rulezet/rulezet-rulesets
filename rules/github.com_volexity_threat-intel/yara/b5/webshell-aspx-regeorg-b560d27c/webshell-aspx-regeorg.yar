rule webshell_aspx_regeorg
{
    meta:
        author = "threatintel@volexity.com"
        date = "2018-08-29"
        description = "Detects the reGeorg webshell based on common strings in the webshell. May also detect other webshells which borrow code from ReGeorg."
        hash = "9d901f1a494ffa98d967ee6ee30a46402c12a807ce425d5f51252eb69941d988"
        os = "win"
        os_arch = "all"
        reference = "https://github.com/L-codes/Neo-reGeorg/blob/master/templates/tunnel.aspx"
        report = "TIB-20231215"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-01-09T10:04:58Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 410
        version = 7

    strings:
        $a1 = "every office needs a tool like Georg" ascii
        $a2 = "cmd = Request.QueryString.Get(\"cmd\")" ascii
        $a3 = "exKak.Message" ascii

        $proxy1 = "if (rkey != \"Content-Length\" && rkey != \"Transfer-Encoding\")"

        $proxy_b1 = "StreamReader repBody = new StreamReader(response.GetResponseStream(), Encoding.GetEncoding(\"UTF-8\"));" ascii
        $proxy_b2 = "string rbody = repBody.ReadToEnd();" ascii
        $proxy_b3 = "Response.AddHeader(\"Content-Length\", rbody.Length.ToString());" ascii

    condition:
        any of ($a*) or
        $proxy1 or
        all of ($proxy_b*)
}