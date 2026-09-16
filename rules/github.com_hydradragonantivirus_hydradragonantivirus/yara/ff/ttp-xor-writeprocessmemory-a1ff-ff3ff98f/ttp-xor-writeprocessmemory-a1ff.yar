rule TTP_XOR_WriteProcessMemory_a1ff {
  strings:
    $key_a1ff = { f6 8d [2] c4 af [2] c2 9a [2] ec 9a [2] d3 86 }

  condition:
    any of them
}