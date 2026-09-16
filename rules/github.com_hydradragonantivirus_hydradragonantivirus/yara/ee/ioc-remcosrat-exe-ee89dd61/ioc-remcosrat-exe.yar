import "hash"
rule IOC_REMCOSRAT_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_REMCOSRAT_LAB"
    date_IOC   = "2023-11-14 10:11:09"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "REMCOSRAT"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "e6324e216c641b6d10f7acbd518cc6d859a842c80e5c58e852e64b6e8a0b7666" or
    hash.sha256(0, filesize) == "39c906f25a69d675d9636c3dcfd78c18cae6a9b7a49697c23a08d54004b4c6ee" or
    hash.sha256(0, filesize) == "3f631c04c084cad9373730dad3b838b4c4f4d079e825ccffdab3b09d12b027c2" or
    hash.sha256(0, filesize) == "82801d63eca2fdd570d211cdffe08f8aeb3ead46d51dec316ca36f389fe29d8b" or
    hash.sha256(0, filesize) == "2abba169b2f3be758c20b3d23dd9fac351a2c6aed1caa97e32ccbbb888e83c80" or
    hash.sha256(0, filesize) == "40870b8167513757fd7d369a7db8f32b828a0ba1540d88324ff19867f9045494" or
    hash.sha256(0, filesize) == "67c980215d2b7daa075a60a95527409258475ab2e6e71a1fa59a18dff0cb0c19" or
    hash.sha256(0, filesize) == "ef9982ce0b9a6a27c0fccc7017093b567663e1ab30bee707bb4316dbfa5e6793" or
    hash.sha256(0, filesize) == "6b17811bf0955ae82d108f30f526b741e15e6f00024cc71b34cc315cd64297b0" or
    hash.sha256(0, filesize) == "d1fc6f72efcb3534ded2e3b870fa01ab945babf2b30d3505573f9f6bb81979eb" or
    hash.sha256(0, filesize) == "f7ea87d7e1c7167b0ee3091546b6740386996794f72ea603c10c4643609b0747" or
    hash.sha256(0, filesize) == "76143c27dd7b0f5017b03d53fffaf18ded8b2c4b310ca61f89b2a6ca78786b7e" or
    hash.sha256(0, filesize) == "7fc8d7dc73ea28fb88262e807b2707ff6bdf2ba3b84ca2b4d866dc5e9e2def8e" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}