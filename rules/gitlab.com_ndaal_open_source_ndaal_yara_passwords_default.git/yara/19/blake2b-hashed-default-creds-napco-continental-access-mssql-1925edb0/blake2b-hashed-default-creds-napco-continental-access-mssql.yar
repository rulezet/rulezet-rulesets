rule blake2b_hashed_default_creds_napco_continental_access_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for napco_continental_access_mssql."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="61c2b079518c20a2f1eab7135fc6c1bff2137269f39becfb0c831853eeb90439c71ece6fd63791e0a2bc35a442c9b9f04496da1fcc80760d3af6ae0fec50588f"
    $a1="61c2b079518c20a2f1eab7135fc6c1bff2137269f39becfb0c831853eeb90439c71ece6fd63791e0a2bc35a442c9b9f04496da1fcc80760d3af6ae0fec50588f"
    $a2="3a68f3b19c9ab7bb4e1809a75946ffed3378b42abc57ed4e3105235b40e8681fce0b1c0f967677f9b7b583423bbb9c79edef0dc71b256788734dbd0fa517abce"
    $a3="61c2b079518c20a2f1eab7135fc6c1bff2137269f39becfb0c831853eeb90439c71ece6fd63791e0a2bc35a442c9b9f04496da1fcc80760d3af6ae0fec50588f"
    $a4="8852ab57ae31da7958a4aa7e7282447b86a5fbc12264cffc7451741c5c9e7dd054f11e2011bc2a4f72caa470ad028a719bce039196614137fae869af966eb3a2"
    $a5="61c2b079518c20a2f1eab7135fc6c1bff2137269f39becfb0c831853eeb90439c71ece6fd63791e0a2bc35a442c9b9f04496da1fcc80760d3af6ae0fec50588f"
    $a6="61c2b079518c20a2f1eab7135fc6c1bff2137269f39becfb0c831853eeb90439c71ece6fd63791e0a2bc35a442c9b9f04496da1fcc80760d3af6ae0fec50588f"
    $a7="fb9aa7f66bb022cbf27109b47727f1630ea82c4ce192d58c3858464ac6a1a853cc475f8b3bd328867273c30b9ba85bf7fa1000d0ece4fd7d1f597e2650e67213"
    $a8="3a68f3b19c9ab7bb4e1809a75946ffed3378b42abc57ed4e3105235b40e8681fce0b1c0f967677f9b7b583423bbb9c79edef0dc71b256788734dbd0fa517abce"
    $a9="fb9aa7f66bb022cbf27109b47727f1630ea82c4ce192d58c3858464ac6a1a853cc475f8b3bd328867273c30b9ba85bf7fa1000d0ece4fd7d1f597e2650e67213"
    $a10="8852ab57ae31da7958a4aa7e7282447b86a5fbc12264cffc7451741c5c9e7dd054f11e2011bc2a4f72caa470ad028a719bce039196614137fae869af966eb3a2"
    $a11="fb9aa7f66bb022cbf27109b47727f1630ea82c4ce192d58c3858464ac6a1a853cc475f8b3bd328867273c30b9ba85bf7fa1000d0ece4fd7d1f597e2650e67213"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}