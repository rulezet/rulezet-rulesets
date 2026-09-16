rule _20160921_2746dcb029094ed409681059b0bf7b68_20160921_4c22609fd731_2822 {
  meta:
    description = "datamaliciousorder - from files 20160921_2746dcb029094ed409681059b0bf7b68.js, 20160921_4c22609fd7310d7f415ca007620a244b.js, 20160921_582a5b9e6263457a7095e1d0bf6ab96b.js, 20160921_6f40563df6afd13be332d60057d492bb.js, 20160921_72cf8bebbcf48b45894fe7d7b3327a58.js, 20160921_be882ab89423f06a9e76ba0cb72775fe.js, 20160921_c9a772728edf4eeff48c1aea32c00a13.js, 20160921_d6eab67b6b3cec2e5f5426840b084b70.js, 20160921_dff46b67b973e99ec02248f10c2f55c2.js, 20160921_e08237183b6bb8840bdab8df29dc62ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9908788e148928c5f3ee88b22ad1ed33dbf69f1ffd103491ebd438b979bb77eb"
    hash2       = "2c98aee98a3263e75913535b49eb469916a931e86a23075b07289143bf0fa3f8"
    hash3       = "ef65e5e7f2b9ad6a0714382fda8dc9fde658333c4a3ea2cdf04558bfe763c3b6"
    hash4       = "f6d3d773ad865f7e3793e6540facc0b8f68d4f503990e93cebc41b933a338a40"
    hash5       = "004799df77a97e1e1816f6a4a1acf9bec5dfd13ae07613832796a6c9ef0cc578"
    hash6       = "fe4f2a5579ff9cbd713377a0d5f78bb0c6c30247b6f455ccdb4014a7c298c978"
    hash7       = "76f52cefe2f1cf5954919532ecd1ec4c5c9072cb4edc435169d570baa9894ed9"
    hash8       = "0ae44892f78e5b5ddfc07e6a23fb55469f21e12c45e74661ad81e61b07893ece"
    hash9       = "2ea0ce06677c6aad57b6618a39beaa56b2c9060cb989c2213eb782aca5d747c2"
    hash10      = "8d131000a0c435e8674de7020c3a970768f0d66e5b0cf5f711017057a318c00f"

  strings:
    $s1 = "00(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Nv\"" ascii
    $s2 = "GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"IPu\";})(),(funct" ascii
    $s3 = " f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe" ascii
    $s4 = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return" ascii
    $s5 = "})(),(function f000(){return \"Um\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Br\";})(),(function f000" ascii
    $s6 = "Gn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"YTp\";})(),(function" ascii
    $s7 = ")(),(function f000(){return \"Rh\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}