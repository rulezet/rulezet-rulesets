rule webshell_jsp_converge
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects CONVERGE - a file upload webshell observed in incident involving compromise of Confluence server via CVE-2022-26134."
        date = "2022-06-01"
        os = "all"
        os_arch = "all"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-09-20T10:58:26Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 6788
        version = 5

    strings:
        $s1 = "if (request.getParameter(\"name\")!=null && request.getParameter(\"name\").length()!=0){" ascii

    condition:
        $s1
}