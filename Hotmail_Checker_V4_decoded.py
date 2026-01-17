#!/usr/bin/env python3
"""
Hotmail Checker V4 - Decoded Source Code
=========================================

ORIGINAL AUTHOR: Ahmed Alhrrani (BY : AHMED ALHRRANI)
DECODED BY: Automatic analysis of Cython-compiled Pyahmed.so

This file is a reconstruction of the original source code based on 
analysis of the compiled Cython (.so) binary. The original code was
compiled with Cython 3.2.3 and targeted Android ARM64 architecture.

Original module name: ahmed17678746192094684.py

NOTE: The exact implementation details of each method cannot be fully 
recovered from compiled code. This reconstruction shows the code 
structure, classes, methods, and their signatures as extracted from
the binary's symbol table and string data.

STRUCTURE OVERVIEW:
- check_time_safety(): License/time validation function
- display_logo(): Shows application banner/logo
- AuthenticationHandler: Handles Microsoft/Outlook authentication
- SVBProfileExtractor: Extracts profile data and searches emails
- CustomKeywordScanner: Searches emails with custom keywords
- ResultHandler: Saves results and sends Telegram notifications
- HotmailScanner: Main scanner class that processes accounts
"""

import os
import sys
import re
import json
import time
import datetime
import requests
from typing import Optional, Dict, List, Any, Tuple


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def check_time_safety() -> bool:
    """
    Validates license/time safety.
    Likely checks if the script is being used within a valid time period
    or validates a license timestamp.
    
    Returns:
        bool: True if time/license check passes, False otherwise
    """
    # Implementation compiled in Cython - exact logic unknown
    # Likely compares current time against embedded timestamp
    pass


def display_logo() -> None:
    """
    Displays the application logo/banner.
    Typically shows ASCII art or colored text banner with:
    - Application name: Hotmail Checker V4
    - Author credit: Ahmed Alhrrani
    - Version information
    """
    # Implementation compiled in Cython
    # Likely uses colorama or similar for colored output
    pass


# ============================================================================
# AUTHENTICATION HANDLER
# ============================================================================

class AuthenticationHandler:
    """
    Handles Microsoft/Outlook/Hotmail OAuth authentication.
    
    Uses Microsoft's OAuth flow to authenticate users and obtain
    access tokens for accessing Outlook/Hotmail mailbox APIs.
    """
    
    def get_auth_code_and_cid(self, login_cookies: Dict[str, str]) -> Tuple[Optional[str], Optional[str]]:
        """
        Retrieves authorization code and CID from Microsoft OAuth flow.
        
        This method performs the OAuth authorization step to get an auth code
        that can be exchanged for an access token.
        
        Args:
            login_cookies: Dictionary containing authentication cookies
                          from successful login (typically includes cookies
                          like 'ESTSAUTH', 'ESTSAUTHPERSISTENT', etc.)
        
        Returns:
            Tuple containing:
                - auth_code: Authorization code for token exchange
                - cid: Client/Customer ID associated with the account
        
        Contains generator expression (genexpr) for processing response data.
        """
        # Implementation compiled in Cython
        # Likely makes requests to:
        # - login.microsoftonline.com
        # - login.live.com
        pass
    
    def get_access_token(self, auth_code: str, cid: str, 
                         client_id: str, redirect_uri: str) -> Optional[str]:
        """
        Exchanges authorization code for an access token.
        
        Performs the OAuth token exchange step using the auth code
        obtained from get_auth_code_and_cid.
        
        Args:
            auth_code: Authorization code from OAuth flow
            cid: Client/Customer ID
            client_id: Application client ID
            redirect_uri: OAuth redirect URI
        
        Returns:
            Access token string if successful, None otherwise
        """
        # Implementation compiled in Cython
        # Makes POST request to Microsoft OAuth token endpoint
        pass


# ============================================================================
# SVB PROFILE EXTRACTOR
# ============================================================================

class SVBProfileExtractor:
    """
    Extracts profile information and searches for specific email types.
    
    Focuses on PlayStation Network (PSN) related emails and store/order
    emails to identify valuable accounts.
    """
    
    def get_extended_profile(self, access_token: str, cid: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves extended profile information from Microsoft/Outlook.
        
        Args:
            access_token: Valid OAuth access token
            cid: Client/Customer ID
        
        Returns:
            Dictionary containing extended profile data including:
            - Display name
            - Email addresses
            - Account type
            - Creation date
            - etc.
        """
        # Implementation compiled in Cython
        pass
    
    def search_playstation_emails(self, access_token: str, cid: str) -> List[Dict[str, Any]]:
        """
        Searches mailbox for PlayStation-related emails.
        
        Looks for emails from PlayStation Network, Sony, PSN Store, etc.
        
        Args:
            access_token: Valid OAuth access token
            cid: Client/Customer ID
        
        Returns:
            List of matching email objects
        """
        # Implementation compiled in Cython
        # Likely searches for keywords like:
        # - "playstation"
        # - "psn"
        # - "sony"
        # - "store.playstation.com"
        pass
    
    def count_psn_emails(self, emails: List[Dict[str, Any]]) -> int:
        """
        Counts the number of PSN-related emails.
        
        Args:
            emails: List of email objects to count
        
        Returns:
            Count of PSN-related emails
        """
        # Implementation compiled in Cython
        pass
    
    def count_store_emails(self, emails: List[Dict[str, Any]]) -> int:
        """
        Counts the number of PlayStation Store-related emails.
        
        Args:
            emails: List of email objects to count
        
        Returns:
            Count of store-related emails (purchases, receipts, etc.)
        """
        # Implementation compiled in Cython
        pass
    
    def extract_preview_message(self, email: Dict[str, Any]) -> str:
        """
        Extracts a preview message from an email object.
        
        Args:
            email: Email object containing message data
        
        Returns:
            Preview string (typically first few lines of email body)
        """
        # Implementation compiled in Cython
        pass
    
    def extract_order_message(self, email: Dict[str, Any]) -> str:
        """
        Extracts order-related information from an email.
        
        Parses emails containing order confirmations, receipts, etc.
        
        Args:
            email: Email object containing order data
        
        Returns:
            Extracted order information string
        """
        # Implementation compiled in Cython
        pass
    
    @staticmethod
    def detect_region_from_text(text: str) -> str:
        """
        Detects the PlayStation region from email text content.
        
        Uses pattern matching to identify region based on:
        - Currency symbols (USD, EUR, GBP, JPY, etc.)
        - Region-specific terms
        - Store URLs (.com, .co.jp, .co.uk, etc.)
        
        Args:
            text: Email text content to analyze
        
        Returns:
            Region code string (e.g., 'US', 'EU', 'JP', 'UK', etc.)
        
        Contains multiple generator expressions for pattern matching.
        """
        # Implementation compiled in Cython
        # Uses genexpr patterns for region detection
        pass
    
    def translate_id_keyword(self, region: str) -> str:
        """
        Translates PlayStation ID keyword based on region.
        
        Args:
            region: Region code
        
        Returns:
            Localized keyword for PSN ID references
        """
        # Implementation compiled in Cython
        pass
    
    def translate_id_change_keyword(self, region: str) -> str:
        """
        Translates ID change notification keyword based on region.
        
        Args:
            region: Region code
        
        Returns:
            Localized keyword for ID change notifications
        """
        # Implementation compiled in Cython
        pass
    
    def translate_order_keyword(self, region: str) -> str:
        """
        Translates order/purchase keyword based on region.
        
        Args:
            region: Region code
        
        Returns:
            Localized keyword for order notifications
        """
        # Implementation compiled in Cython
        pass
    
    def search_id_change(self, access_token: str, cid: str, 
                         keyword: str) -> List[Dict[str, Any]]:
        """
        Searches for PSN ID change notification emails.
        
        Args:
            access_token: Valid OAuth access token
            cid: Client/Customer ID
            keyword: Localized search keyword
        
        Returns:
            List of matching ID change notification emails
        """
        # Implementation compiled in Cython
        pass
    
    def search_orders(self, access_token: str, cid: str,
                      keyword: str) -> List[Dict[str, Any]]:
        """
        Searches for PlayStation Store order/purchase emails.
        
        Args:
            access_token: Valid OAuth access token
            cid: Client/Customer ID  
            keyword: Localized search keyword
        
        Returns:
            List of matching order emails
        """
        # Implementation compiled in Cython
        pass


# ============================================================================
# CUSTOM KEYWORD SCANNER
# ============================================================================

class CustomKeywordScanner:
    """
    Allows searching mailbox with custom keywords.
    
    Provides flexibility to search for any type of email content
    beyond the built-in PlayStation-related searches.
    """
    
    def search_with_keyword(self, access_token: str, cid: str,
                           keyword: str) -> List[Dict[str, Any]]:
        """
        Searches mailbox using a custom keyword.
        
        Args:
            access_token: Valid OAuth access token
            cid: Client/Customer ID
            keyword: Custom keyword to search for
        
        Returns:
            List of matching email objects
        """
        # Implementation compiled in Cython
        pass


# ============================================================================
# RESULT HANDLER
# ============================================================================

class ResultHandler:
    """
    Handles saving results and sending notifications.
    
    Supports:
    - Saving results to local files
    - Sending notifications via Telegram bot
    - Formatting results for display
    """
    
    def save_to_file(self, filename: str, data: str, 
                     mode: str = 'a') -> None:
        """
        Saves result data to a file.
        
        Args:
            filename: Output filename
            data: Data to write
            mode: File open mode (default: append)
        """
        # Implementation compiled in Cython
        pass
    
    def send_telegram_notification(self, bot_token: str, chat_id: str,
                                   message: str) -> bool:
        """
        Sends a notification message via Telegram bot.
        
        Args:
            bot_token: Telegram bot API token
            chat_id: Target chat/channel ID
            message: Message content to send
        
        Returns:
            True if message sent successfully, False otherwise
        """
        # Implementation compiled in Cython
        # Uses Telegram Bot API: https://api.telegram.org/bot<token>/sendMessage
        pass
    
    def format_svb_psn_results(self, email: str, password: str,
                               profile: Dict[str, Any],
                               psn_emails: List[Dict[str, Any]],
                               region: str, **kwargs) -> str:
        """
        Formats SVB/PSN results for display and saving.
        
        Creates a formatted string containing:
        - Account credentials
        - Profile information
        - PSN email statistics
        - Detected region
        - Additional metadata
        
        Args:
            email: Account email address
            password: Account password
            profile: Extended profile data
            psn_emails: List of PSN-related emails found
            region: Detected PlayStation region
            **kwargs: Additional result data
        
        Returns:
            Formatted result string
        """
        # Implementation compiled in Cython
        pass


# ============================================================================
# HOTMAIL SCANNER (MAIN SCANNER CLASS)
# ============================================================================

class HotmailScanner:
    """
    Main scanner class that processes Hotmail/Outlook accounts.
    
    Coordinates the authentication, profile extraction, email searching,
    and result handling for batch account processing.
    """
    
    def process_and_save(self, email: str, password: str,
                         bot_token: Optional[str] = None,
                         chat_id: Optional[str] = None,
                         output_file: Optional[str] = None,
                         **options) -> Dict[str, Any]:
        """
        Processes a single account and saves results.
        
        Complete workflow:
        1. Authenticate with Microsoft
        2. Get access token
        3. Extract profile information
        4. Search for PlayStation emails
        5. Detect region
        6. Format and save results
        7. Send Telegram notification (if configured)
        
        Args:
            email: Account email address
            password: Account password
            bot_token: Optional Telegram bot token
            chat_id: Optional Telegram chat ID
            output_file: Optional output filename
            **options: Additional processing options
        
        Returns:
            Dictionary containing:
            - success: bool
            - profile: profile data (if successful)
            - psn_count: count of PSN emails
            - region: detected region
            - error: error message (if failed)
        """
        # Implementation compiled in Cython
        pass
    
    def process(self, email: str, password: str,
                cookies: Optional[Dict[str, str]] = None,
                **options) -> Dict[str, Any]:
        """
        Processes a single account without saving.
        
        Performs authentication and data extraction without
        saving results or sending notifications.
        
        Args:
            email: Account email address
            password: Account password
            cookies: Optional pre-existing cookies
            **options: Additional processing options
        
        Returns:
            Dictionary containing processing results
        
        Contains generator expression (genexpr) for data processing.
        """
        # Implementation compiled in Cython
        pass


# ============================================================================
# MAIN ENTRY POINT (Original loader code)
# ============================================================================

def main():
    """
    Original loader entry point.
    
    The original Hotmail Checker V4.py file contains a loader that:
    1. Base64 decodes an embedded zip file
    2. Extracts it to a temporary directory (~/.pyprivate)
    3. Runs __main__.py which:
       a. Base85 decodes another layer
       b. Sets up Python environment variables
       c. Executes the Pyahmed.so compiled module
    4. Cleans up the temporary directory on exit
    
    The loader code (from original file):
    
    ```python
    #BY : AHMED ALHRRANI
    import os
    import shutil
    import zipfile
    import subprocess
    import base64
    import atexit
    
    MyHome = os.path.expanduser("~")
    Pyprivate = os.path.join(MyHome, ".pyprivate")
    
    def cleanup():
        if os.path.exists(Pyprivate):
            try:
                shutil.rmtree(Pyprivate)
                print("Done")
            except:
                pass
    
    atexit.register(cleanup)
    
    AH = "<base64 encoded zip data>"  # ~550KB of base64 data
    Dev = base64.b64decode(AH)
    
    if not os.path.exists(Pyprivate):
        os.makedirs(Pyprivate)
    
    Mahos = os.path.join(Pyprivate, "CanYou")
    with open(Mahos, "wb") as f:
        f.write(Dev)
    
    with zipfile.ZipFile(Mahos, 'r') as zip_ref:
        zip_ref.extractall(Pyprivate)
    
    pyahmed_path = os.path.join(Pyprivate, "Pyahmed.so")
    os.chmod(pyahmed_path, 0o755)
    
    Do_Not = os.path.join(Pyprivate, "__main__.py")
    try:
        subprocess.run(["python", Do_Not], check=True, cwd=Pyprivate)
        shutil.rmtree(Pyprivate)
    except subprocess.CalledProcessError as e:
        print(e)
        shutil.rmtree(Pyprivate)
    ```
    
    The __main__.py (Base85 decoded):
    
    ```python
    import os
    import sys
    
    # Sets PYTHONHOME and PYTHON_EXECUTABLE environment variables
    # Then executes ./Pyahmed.so
    os.system(
        "export PYTHONHOME=" + sys.prefix + 
        " && export PYTHON_EXECUTABLE=" + sys.executable + 
        " && ./Pyahmed.so"
    )
    ```
    """
    # The actual entry point is in the compiled Pyahmed.so
    # which contains the check_time_safety(), display_logo(), 
    # and main scanning logic
    pass


if __name__ == "__main__":
    main()


# ============================================================================
# ADDITIONAL NOTES
# ============================================================================
"""
TECHNICAL DETAILS
-----------------

1. Compilation:
   - Original source: ahmed17678746192094684.py
   - Compiler: Cython 3.2.3
   - Target: ARM64 (aarch64) Android
   - Android linker: /system/bin/linker64
   - Python version: 3.11

2. Library:
   - Uses "Backcompat" library for Android
   - Licensed to: IIEC developer (iiecdev@gmail.com)
   - Copyright: n0n3m4 (Roman Lebedev) 2023

3. Core Functionality:
   - Microsoft/Outlook OAuth authentication
   - Outlook/Hotmail mailbox access via API
   - PlayStation Network email detection
   - Region detection (US, EU, JP, UK, etc.)
   - Order/purchase email parsing
   - Telegram notification support
   - File-based result storage

4. Extracted Class/Method Signatures:
   
   Functions:
   - check_time_safety() -> checks license validity
   - display_logo() -> shows app banner
   
   AuthenticationHandler:
   - get_auth_code_and_cid(login_cookies) -> (auth_code, cid)
   - get_access_token(auth_code, cid, client_id, redirect_uri) -> token
   
   SVBProfileExtractor:
   - get_extended_profile(access_token, cid) -> profile
   - search_playstation_emails(access_token, cid) -> emails
   - count_psn_emails(emails) -> count
   - count_store_emails(emails) -> count
   - extract_preview_message(email) -> preview
   - extract_order_message(email) -> order_info
   - detect_region_from_text(text) -> region (static)
   - translate_id_keyword(region) -> keyword
   - translate_id_change_keyword(region) -> keyword
   - translate_order_keyword(region) -> keyword
   - search_id_change(access_token, cid, keyword) -> emails
   - search_orders(access_token, cid, keyword) -> emails
   
   CustomKeywordScanner:
   - search_with_keyword(access_token, cid, keyword) -> emails
   
   ResultHandler:
   - save_to_file(filename, data, mode) -> None
   - send_telegram_notification(bot_token, chat_id, message) -> bool
   - format_svb_psn_results(...) -> formatted_string
   
   HotmailScanner:
   - process_and_save(email, password, bot_token, chat_id, output_file, **options) -> results
   - process(email, password, cookies, **options) -> results

5. Limitations of This Reconstruction:
   - Exact implementation details are not available (compiled to native code)
   - API endpoints and URLs are not fully recoverable
   - String constants may be compressed or obfuscated
   - Error handling logic is not visible
   - Regex patterns for email parsing are not recoverable

DISCLAIMER
----------
This decoded source code is provided for educational purposes only.
The original code performs email account checking which may violate
terms of service of email providers and potentially applicable laws.
Use responsibly and in accordance with applicable laws and terms of service.
"""
