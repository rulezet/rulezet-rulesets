rule ChinaChopper_one {
    meta:
        description = "Chinese Hacktool Set - file one.asp"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "6cd28163be831a58223820e7abe43d5eacb14109"
        id = "854fb5c9-38c7-5fd2-a473-66ae297070f5"
    strings:
        $s0 = "<%eval request(" ascii
    condition:
        filesize < 50 and all of them
}