rule backdoor_win_warhawk {
  meta:
    id             = "d0ec19a7-cb08-4bca-b153-d7b0358186b4"
    version        = "1.0"
    description    = "Detect the WarHawk backdoor used by the SideWinder intrusion-set"
    author         = "Sekoia.io"
    creation_date  = "2022-10-24"
    classification = "TLP:CLEAR"
    reference      = "https://www.zscaler.com/blogs/security-research/warhawk-new-backdoor-arsenal-sidewinder-apt-group-0"
    hash_exe1      = "7d3574c62df44b74337fc74ec7877792b4ffa1486a49bb19668433c3ca8836b5"
    hash_exe2      = "624c6b56ee3865f4a5792ad1946a8e86b876440a5af3bac22ac1dee92f1b7372"
    hash_iso1      = "58b3686e4255d32dbcf7dee9dac1d5be6d4692d086cde167da1e1a5e0e1b315a"
    hash_iso2      = "f97d5d3e1c2ceb3e9d23ae5b5d4e7c9857155df5acf7f67fee995cb041c797dc"

  strings:
        $ = "{ \\\"name\\\": \\\"%s\\\", \\\"size\\\": \\\"\\\", \\\"mod\\\": \\\"%s\\\", \\\"type\\\": \\\"File folder\\\" },"

        
        $ = "{ \"_hwid\": \"%s\", \"_computer\": \"%s\", \"_username\": \"%s\", \"_os\": \"%s\" }"

        $ = "{\\\"name\\\": \\\"%s\\\", \\\"type\\\": \\\"%s\\\"},"

        $ = "{ \"_hwid\": \"%s\", \"_filemgr_done\": \"true\", \"_response\": \"%s\" }"

        $ = "{ \"_hwid\": \"%s\", \"_task\": \"true\" }"

        $ = "{ \"_hwid\": \"%s\", \"_task_done\": \"true\", \"_id\": \"%s\" }"

        $ = "{ \"_hwid\": \"%s\", \"_cmd\": \"true\" }"

        $ = "{ \"_hwid\": \"%s\", \"_cmd_done\": \"true\", \"_response\": \"%s\" }"

        $ = "{ \"_hwid\": \"%s\", \"_filemgr\": \"true\" }"

        $ = "{ \"_hwid\": \"%s\" }"

        $ = "{ \"_hwid\": \"%s\", \"_ping\": \"true\" }"

    $ = "cmd.exe"

  condition:
    all of them
}