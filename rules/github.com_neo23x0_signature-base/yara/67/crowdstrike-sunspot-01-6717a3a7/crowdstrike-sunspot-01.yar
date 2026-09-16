rule CrowdStrike_SUNSPOT_01 : artifact stellarparticle sunspot {

    meta:
        author = "(c) 2021 CrowdStrike Inc."
        description = "Detects RC4 and AES key encryption material in SUNSPOT"
        reference = "https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/"
        version = "202101081448"
        date = "2021-01-08"
        actor = "StellarParticle"
        malware_family = "SUNSPOT"

        id = "2a2a5cfc-d059-5942-bd70-c3169e9ceb45"
    strings:

        $key = {fc f3 2a 83 e5 f6 d0 24 a6 bf ce 88 30 c2 48 e7}
        $iv  = {81 8c 85 49 b9 00 06 78 0b e9 63 60 26 64 b2 da}

    condition:
        all of them and filesize < 32MB

}