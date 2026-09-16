rule ChinaChopper_temp_2 {
    meta:
        description = "Chinese Hacktool Set - file temp.php"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "604a4c07161ce1cd54aed5566e5720161b59deee"
        id = "3952ed2b-fb27-5c45-9cd7-b7a300b37c0e"
    strings:
        $s0 = "@eval($_POST[strtoupper(md5(gmdate(" ascii
    condition:
        filesize < 150 and all of them
}