rule TTP_XOR_WriteProcessMemory_a10f {
  strings:
    $key_a10f = { f6 7d [2] c4 5f [2] c2 6a [2] ec 6a [2] d3 76 }

  condition:
    any of them
}