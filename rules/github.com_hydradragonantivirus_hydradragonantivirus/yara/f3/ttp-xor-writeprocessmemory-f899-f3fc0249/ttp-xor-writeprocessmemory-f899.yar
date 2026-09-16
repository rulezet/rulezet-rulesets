rule TTP_XOR_WriteProcessMemory_f899 {
  strings:
    $key_f899 = { af eb [2] 9d c9 [2] 9b fc [2] b5 fc [2] 8a e0 }

  condition:
    any of them
}