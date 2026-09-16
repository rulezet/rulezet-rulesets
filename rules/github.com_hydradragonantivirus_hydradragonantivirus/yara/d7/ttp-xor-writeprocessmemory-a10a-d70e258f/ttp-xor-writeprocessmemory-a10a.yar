rule TTP_XOR_WriteProcessMemory_a10a {
  strings:
    $key_a10a = { f6 78 [2] c4 5a [2] c2 6f [2] ec 6f [2] d3 73 }

  condition:
    any of them
}