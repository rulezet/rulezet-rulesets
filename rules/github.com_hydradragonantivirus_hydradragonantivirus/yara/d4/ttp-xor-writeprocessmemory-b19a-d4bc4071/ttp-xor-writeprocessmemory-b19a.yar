rule TTP_XOR_WriteProcessMemory_b19a {
  strings:
    $key_b19a = { e6 e8 [2] d4 ca [2] d2 ff [2] fc ff [2] c3 e3 }

  condition:
    any of them
}