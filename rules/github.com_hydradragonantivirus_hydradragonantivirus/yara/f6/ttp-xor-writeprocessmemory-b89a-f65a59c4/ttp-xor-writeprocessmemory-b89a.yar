rule TTP_XOR_WriteProcessMemory_b89a {
  strings:
    $key_b89a = { ef e8 [2] dd ca [2] db ff [2] f5 ff [2] ca e3 }

  condition:
    any of them
}