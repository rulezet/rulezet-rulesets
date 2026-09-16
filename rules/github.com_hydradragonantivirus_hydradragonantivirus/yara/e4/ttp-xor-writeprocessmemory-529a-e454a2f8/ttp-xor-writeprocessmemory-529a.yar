rule TTP_XOR_WriteProcessMemory_529a {
  strings:
    $key_529a = { 05 e8 [2] 37 ca [2] 31 ff [2] 1f ff [2] 20 e3 }

  condition:
    any of them
}