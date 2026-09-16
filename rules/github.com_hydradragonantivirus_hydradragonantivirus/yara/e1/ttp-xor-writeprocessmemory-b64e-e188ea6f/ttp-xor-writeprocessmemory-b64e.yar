rule TTP_XOR_WriteProcessMemory_b64e {
  strings:
    $key_b64e = { e1 3c [2] d3 1e [2] d5 2b [2] fb 2b [2] c4 37 }

  condition:
    any of them
}