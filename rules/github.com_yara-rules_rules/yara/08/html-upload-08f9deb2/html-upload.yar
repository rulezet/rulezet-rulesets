rule html_upload {
    strings: 
        $ = "<input type='submit' name='upload' value='upload'>"
        $ = "if($_POST['upload'])"
    condition: 
        any of them and filesize < 500KB
}