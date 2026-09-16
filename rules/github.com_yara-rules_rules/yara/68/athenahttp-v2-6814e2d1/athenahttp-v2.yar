rule AthenaHTTP_v2 
{
    
    meta:
        author = "Jason Jones <jasonjones@arbor.net>"
        description = "Athena HTTP identification"
        source = "https://github.com/arbor/yara/blob/master/athena.yara"

    strings:
        $fmt_str1="|type:on_exec|uid:%s|priv:%s|arch:x%s|gend:%s|cores:%i|os:%s|ver:%s|net:%s|"
        $fmt_str2="|type:repeat|uid:%s|ram:%ld|bk_killed:%i|bk_files:%i|bk_keys:%i|busy:%s|"
        $cmd1 = "filesearch.stop"
        $cmd2 = "rapidget"
        $cmd3 = "layer4."
        $cmd4 = "slowloris"
        $cmd5 = "rudy"
   
    condition:
        all of ($fmt_str*) and 3 of ($cmd*)
}