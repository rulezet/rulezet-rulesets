rule finspy_android_dexden: android dexhideconfig finspy {
  meta:
    description = "Detect FinFisher FinSpy configuration in DEX file. Probably a newer FinSpy variant."
    date        = "2020/08/05"
    author      = "Esther Onfroy a.k.a U+039b - *@0x39b.fr (https://twitter.com/u039b)"

  strings:
    $config_1 = { 90 5b fe 00 }
    $config_2 = { 70 37 80 00 }
    $config_3 = { 40 38 80 00 }
    $config_4 = { a0 33 84 }
    $config_5 = { 90 79 84 00 }

  condition:
    uint16(0) == 0x6564 and
    #config_1 >= 2 and
    #config_2 >= 2 and
    #config_3 >= 2 and
    #config_4 >= 2 and
    #config_5 >= 2
}