rule Brooxml_Phishing {
    meta:
        description = "Detects PDF and OOXML files leading to AiTM phishing"
        author = "Proofpoint"
        category = "phishing"
        date = "2024-11-27"
        score = 65
        reference = "https://x.com/threatinsight/status/1861817946508763480"
        id = "ccd8ab30-90a4-5d4b-8a77-dbc4669bdb95"
    strings:
        $hex1 = { 21 20 03 20 c3 be c3 bf 09 20 [0-1] 06 20 20 20 20 20 20 20 20 20 20 20 01 20 20 20 06 20 20 20 20 20 20 20 20 10 20 20 05 20 20 20 01 20 20 20 c3 be c3 bf c3 bf c3 bf }
    condition:
        all of ($hex*) and ((uint16be(0) == 0x504b) or (uint32be(0) == 0x25504446))
}