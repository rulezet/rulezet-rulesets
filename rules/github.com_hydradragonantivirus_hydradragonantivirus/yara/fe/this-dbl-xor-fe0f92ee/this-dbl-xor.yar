rule this_dbl_xor {
  meta:
    author = "@tylabs"
    hash   = "d85d54434e990e84a28862523c277057"

  strings:
    $a = { 86 BB BD A6 F6 A7 5A 46 4D 59 4D 40 0E 4C 41 4F 4C 4C 50 05 44 42 18 4B 4F 55 1C 54 50 1F 74 7E 61 13 59 5A 52 52 }

  condition:
    any of them
}