rule TTP_XOR_WriteProcessMemory_4cca {
  strings:
    $key_4cca = { 1b b8 [2] 29 9a [2] 2f af [2] 01 af [2] 3e b3 }

  condition:
    any of them
}