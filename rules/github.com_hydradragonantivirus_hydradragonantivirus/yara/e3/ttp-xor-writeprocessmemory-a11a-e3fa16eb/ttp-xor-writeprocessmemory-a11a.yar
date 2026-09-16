rule TTP_XOR_WriteProcessMemory_a11a {
  strings:
    $key_a11a = { f6 68 [2] c4 4a [2] c2 7f [2] ec 7f [2] d3 63 }

  condition:
    any of them
}