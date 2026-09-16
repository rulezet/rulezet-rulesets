rule TTP_XOR_WriteProcessMemory_7bca {
  strings:
    $key_7bca = { 2c b8 [2] 1e 9a [2] 18 af [2] 36 af [2] 09 b3 }

  condition:
    any of them
}