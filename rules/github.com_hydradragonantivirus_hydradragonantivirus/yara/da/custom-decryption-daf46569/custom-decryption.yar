rule custom_decryption {
  meta:
    author = "Etienne Maynier"
    email  = "etienne@citizenlab.ca"

  strings:
    $encrypt       = { 8b d6 81 e2 07 00 00 80 79 05 4a 83 ca f8 42 8a 04 1e 0f be 0c 95 28 7e 46 00 34 01 0f be c0 0f af c8 80 f1 67 88 0c 1e 46 3b f7 7c d3 }
    $encrypt2      = { 8A 0C 30 8B D0 83 E2 07 80 F1 01 0F BE C9 0F BE 54 95 D0 0F AF D1 80 F2 85 88 14 30 40 }
    $decrypt_file1 = { 0f b6 01 8b d6 83 e2 07 34 01 0f be c0 83 c6 04 0f be }
    $decrypt_file2 = { 0f af d0 0f b6 41 01 34 01 0f be c0 88 11 8d 14 0f 83 e2 07 0f be }
    $decrypt_file3 = { 0f af d0 0f b6 41 02 34 01 0f be c0 88 51 01 8d 14 0b 83 e2 07 0f be }
    $decrypt_file4 = { 0f af d0 0f b6 41 03 34 01 0f be c0 88 51 02 8b 55 fc 03 d1 83 e2 07 0f be }

  condition:
    uint16(0) == 0x5A4D and ($encrypt or $encrypt2 or all of ($decrypt_file*))
}