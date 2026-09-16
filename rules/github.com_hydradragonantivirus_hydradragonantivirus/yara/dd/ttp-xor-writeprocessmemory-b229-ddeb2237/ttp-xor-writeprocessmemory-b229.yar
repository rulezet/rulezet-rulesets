rule TTP_XOR_WriteProcessMemory_b229 {
  strings:
    $key_b229 = { e5 5b [2] d7 79 [2] d1 4c [2] ff 4c [2] c0 50 }

  condition:
    any of them
}