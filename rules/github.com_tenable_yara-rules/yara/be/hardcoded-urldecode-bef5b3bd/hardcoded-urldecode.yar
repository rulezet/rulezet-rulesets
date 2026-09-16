rule hardcoded_urldecode
{
    meta:
        description = "PHP with hard coded urldecode call"
        family = "PHP.Obfuscated"
        filetype = "PHP"
        hash = "79b22d7dbf49d8cfdc564936c8a6a1e2"
        hash = "38dc8383da0859dca82cf0c943dbf16d"

    strings:
        $obf = /urldecode[\t ]*\([\t ]*'(%[0-9a-fA-F][0-9a-fA-F])+'[\t ]*\)/

    condition:
        all of them
}