rule apt_webshell_aspx_sportsball
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-03-01"
        description = "The SPORTSBALL webshell, observed in targeted Microsoft Exchange attacks in 2021. SPORTSBALL was later discovered to be a variant of HYPERSHELL, a publicly available webshell."
        hash = "2fa06333188795110bba14a482020699a96f76fb1ceb80cbfa2df9d3008b5b0a"
        os = "win"
        os_arch = "all"
        reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
        reference2 = "https://github.com/misterch0c/APT34/blob/e62f3d14ec78bea5c98d3c895162ca1e47676c18/Webshells_and_Panel/HyperShell/HyperShell/Shell/simple.aspx"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2025-07-24T09:43:13Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 4968
        version = 6

    strings:
        $uniq1 = "HttpCookie newcook = new HttpCookie(\"fqrspt\", HttpContext.Current.Request.Form"
        $uniq2 = "ZN2aDAB4rXsszEvCLrzgcvQ4oi5J1TuiRULlQbYwldE="

        $s1 = "Result.InnerText = string.Empty;"
        $s2 = "newcook.Expires = DateTime.Now.AddDays("
        $s3 = "System.Diagnostics.Process process = new System.Diagnostics.Process();"
        $s4 = "process.StandardInput.WriteLine(HttpContext.Current.Request.Form[\""
        $s5 = "else if (!string.IsNullOrEmpty(HttpContext.Current.Request.Form[\""
        $s6 = "<input type=\"submit\" value=\"Upload\" />"

    condition:
        any of ($uniq*) or
        all of ($s*)
}