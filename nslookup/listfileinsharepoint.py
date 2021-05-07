from office365.runtime.auth.authentication_context import AuthenticationContext
from office365.sharepoint.client_context import ClientContext
from office365.sharepoint.files.file import File
from office365.runtime.auth.user_credential import UserCredential
from office365.sharepoint.files.file_system_object_type import FileSystemObjectType
import io
import pandas as pd
import openpyxl
import json
from pprint import PrettyPrinter, pprint

def enum_files_and_folders(url,username,password,folder):
    """
    :type target_list: List
    """
    SP_SITE_URL = url
    USERNAME =username
    PASSWORD =password
    ctx_auth = AuthenticationContext(url)
    if ctx_auth.acquire_token_for_user(username, password):
        ctx = ClientContext(url, ctx_auth)
        web = ctx.web
        ctx.load(web)
        ctx.execute_query()
    target_list = ctx.web.lists.get_by_title(folder)
    ctx =ClientContext(SP_SITE_URL).with_user_credentials(USERNAME, PASSWORD)
    items = target_list.items.select(["FileSystemObjectType"]).expand(["File", "Folder"])
    ctx.load(items)
    ctx.execute_query()
    for item in items:
        if item.properties["FileSystemObjectType"] == FileSystemObjectType.Folder:
            print("Folder url: {0}".format(item.folder.serverRelativeUrl))
        else:
            print("File url: {0}".format(item.file.serverRelativeUrl))

if __name__ == '__main__':
    enum_files_and_folders("https://3cxcloudonline.sharepoint.com/sites/IDBCorporation","bruce@idb.com.vn","Minhtam123","Documents")
