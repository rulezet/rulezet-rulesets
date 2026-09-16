rule TTP_XOR_WriteProcessMemory_7bdd {
  strings:
    $key_7bdd = { 2c af [2] 1e 8d [2] 18 b8 [2] 36 b8 [2] 09 a4 }

  condition:
    any of them
}