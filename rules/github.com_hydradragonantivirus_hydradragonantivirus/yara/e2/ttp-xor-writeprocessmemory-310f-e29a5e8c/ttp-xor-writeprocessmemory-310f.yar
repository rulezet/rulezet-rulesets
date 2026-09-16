rule TTP_XOR_WriteProcessMemory_310f {
  strings:
    $key_310f = { 66 7d [2] 54 5f [2] 52 6a [2] 7c 6a [2] 43 76 }

  condition:
    any of them
}