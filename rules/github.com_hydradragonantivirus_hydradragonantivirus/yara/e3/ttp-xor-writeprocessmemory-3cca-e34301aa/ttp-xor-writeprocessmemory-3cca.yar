rule TTP_XOR_WriteProcessMemory_3cca {
  strings:
    $key_3cca = { 6b b8 [2] 59 9a [2] 5f af [2] 71 af [2] 4e b3 }

  condition:
    any of them
}