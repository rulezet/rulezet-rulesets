rule TTP_XOR_WriteProcessMemory_ddaf {
  strings:
    $key_ddaf = { 8a dd [2] b8 ff [2] be ca [2] 90 ca [2] af d6 }

  condition:
    any of them
}