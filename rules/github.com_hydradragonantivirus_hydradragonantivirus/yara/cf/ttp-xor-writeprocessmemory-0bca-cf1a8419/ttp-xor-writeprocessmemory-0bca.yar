rule TTP_XOR_WriteProcessMemory_0bca {
  strings:
    $key_0bca = { 5c b8 [2] 6e 9a [2] 68 af [2] 46 af [2] 79 b3 }

  condition:
    any of them
}