rule md5_50be694a82a8653fa8b31d049aac721a {
    strings: $ = "(preg_match('/\\/admin\\/Cms_Wysiwyg\\/directive\\/index\\//', $_SERVER['REQUEST_URI']))"
    condition: any of them
}