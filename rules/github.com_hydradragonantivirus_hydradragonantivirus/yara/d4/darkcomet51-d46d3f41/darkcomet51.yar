rule darkcomet51: rat {
    meta:
        rule_group = "implant"
        implant = "darkcomet51"
        
        description = "DarkComet RAT version 5.1"
        id = "CSE_900015"
        organisation = "CSE"
        poc = "malware_dev@cse"
        rule_version = "1"
        yara_version = "3.4"
        
        author = "CCIRC"
        creation_date = "2016-03-23T15:26:52.162005Z"
        date = "2015-11-16"
        last_saved_by = "malware_dev"
        al_configparser = "DarkComet51"
        al_imported_by = "malware_dev"
        al_status = "DEPLOYED"
    
    strings:
        $config = "D57ABA5857F0AFF67584605E90BE4665C9814BEEC7E"
    
    condition:
        any of them
    
}