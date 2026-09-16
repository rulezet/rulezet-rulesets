rule TTP_XOR_WriteProcessMemory_eb0d {
  strings:
    $key_eb0d = { bc 7f [2] 8e 5d [2] 88 68 [2] a6 68 [2] 99 74 }

  condition:
    any of them
}