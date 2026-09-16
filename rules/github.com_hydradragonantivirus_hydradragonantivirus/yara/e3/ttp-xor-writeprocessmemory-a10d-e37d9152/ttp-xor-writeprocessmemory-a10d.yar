rule TTP_XOR_WriteProcessMemory_a10d {
  strings:
    $key_a10d = { f6 7f [2] c4 5d [2] c2 68 [2] ec 68 [2] d3 74 }

  condition:
    any of them
}