rule webshell_jsp_godzilla
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the JSP implementation of the Godzilla Webshell."
        date = "2021-11-08"
        hash1 = "2786d2dc738529a34ecde10ffeda69b7f40762bf13e7771451f13a24ab7fc5fe"
        os = "win,linux"
        os_arch = "all"
        reference = "https://github.com/BeichenDream/Godzilla"
        reference2 = "https://unit42.paloaltonetworks.com/manageengine-godzilla-nglite-kdcsponge/"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-07-30T09:08:00Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 6100
        version = 6

    strings:
        $s1 = ".getWriter().write(base64Encode(" wide ascii
        $s2 = ".getAttribute(" ascii wide
        $s3 = "java.security.MessageDigest" ascii wide

        $auth1 = /String xc=\"[a-f0-9]{16}\"/ ascii wide
        $auth2 = "String pass=\"" ascii wide

        $magic = "class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q"
        $magic2 = "<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class"

    condition:
        all of ($s*) or
        all of ($auth*) or
        any of ($magic*)
}