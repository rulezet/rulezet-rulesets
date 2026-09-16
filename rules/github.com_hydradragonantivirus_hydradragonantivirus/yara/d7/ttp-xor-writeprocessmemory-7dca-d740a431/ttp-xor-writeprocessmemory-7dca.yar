rule TTP_XOR_WriteProcessMemory_7dca {
  strings:
    $key_7dca = { 2a b8 [2] 18 9a [2] 1e af [2] 30 af [2] 0f b3 }

  condition:
    any of them
}