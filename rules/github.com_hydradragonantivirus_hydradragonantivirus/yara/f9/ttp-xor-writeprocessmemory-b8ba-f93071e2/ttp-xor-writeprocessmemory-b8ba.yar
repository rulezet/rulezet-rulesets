rule TTP_XOR_WriteProcessMemory_b8ba {
  strings:
    $key_b8ba = { ef c8 [2] dd ea [2] db df [2] f5 df [2] ca c3 }

  condition:
    any of them
}