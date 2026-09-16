rule TTP_XOR_WriteProcessMemory_af99 {
  strings:
    $key_af99 = { f8 eb [2] ca c9 [2] cc fc [2] e2 fc [2] dd e0 }

  condition:
    any of them
}