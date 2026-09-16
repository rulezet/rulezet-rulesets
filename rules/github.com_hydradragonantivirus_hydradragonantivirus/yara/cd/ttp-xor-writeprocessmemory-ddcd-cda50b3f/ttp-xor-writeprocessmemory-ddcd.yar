rule TTP_XOR_WriteProcessMemory_ddcd {
  strings:
    $key_ddcd = { 8a bf [2] b8 9d [2] be a8 [2] 90 a8 [2] af b4 }

  condition:
    any of them
}