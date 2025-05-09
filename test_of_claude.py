import os
import random
import string
import base64
import hashlib
import json
import time
import uuid
from datetime import datetime


class RansomwareDetectionTester:
    def __init__(self, folder_path="monitored_dir", num_files=20, file_size_range=(500, 2000)):
        """
        Initialize the ransomware detection tester.

        Args:
            folder_path: Path to the test folder
            num_files: Number of test files to create
            file_size_range: Range of file sizes (min, max) in characters
        """
        self.folder_path = folder_path
        self.num_files = num_files
        self.file_size_range = file_size_range
        self.file_records = {}
        self.encrypted_files = []
        self.legitimately_modified_files = []
        self.generated_files = []

        # Generate a unique identifier for this test run
        self.test_id = str(uuid.uuid4())[:8]

        # Create test folder if it doesn't exist
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
            print(f"Created test folder at {folder_path}")
        else:
            print(f"Using existing folder at {folder_path}")

    def generate_random_ascii_content(self, size):
        """Generate random ASCII content of specified size"""
        valid_chars = string.ascii_letters + string.digits + string.punctuation + ' \n\t'
        return ''.join(random.choice(valid_chars) for _ in range(size))

    def create_test_files(self):
        """Create test files with random ASCII content"""
        print(f"Creating {self.num_files} new test files in {self.folder_path}...")

        for i in range(self.num_files):
            # Use a unique filename to avoid overwriting existing files
            filename = f"test_{self.test_id}_file_{i}.txt"
            filepath = os.path.join(self.folder_path, filename)

            # Generate random content size
            content_size = random.randint(self.file_size_range[0], self.file_size_range[1])
            content = self.generate_random_ascii_content(content_size)

            # Write content to file
            with open(filepath, 'w', encoding='ascii') as f:
                f.write(content)

            # Store original file hash
            file_hash = hashlib.sha256(content.encode('ascii')).hexdigest()
            self.file_records[filename] = {
                'original_hash': file_hash,
                'status': 'original',
                'modification_time': datetime.now().isoformat()
            }

            self.generated_files.append(filename)

        print(f"Created {self.num_files} new files successfully.")

    def perform_legitimate_modifications(self, percentage=30):
        """Perform legitimate modifications on a percentage of files"""
        # Only modify files that we created in this test run
        num_files_to_modify = int(len(self.generated_files) * percentage / 100)
        files_to_modify = random.sample(self.generated_files, num_files_to_modify)

        print(f"Performing legitimate modifications on {num_files_to_modify} files...")

        for filename in files_to_modify:
            filepath = os.path.join(self.folder_path, filename)

            # Read current content
            with open(filepath, 'r', encoding='ascii') as f:
                content = f.read()

            # Choose a random modification type
            mod_type = random.choice([
                'append_text',
                'prepend_text',
                'modify_random_line',
                'delete_random_line',
                'replace_words'
            ])

            if mod_type == 'append_text':
                # Append text to the end
                content += "\n" + self.generate_random_ascii_content(random.randint(10, 100))

            elif mod_type == 'prepend_text':
                # Add text at the beginning
                content = self.generate_random_ascii_content(random.randint(10, 100)) + "\n" + content

            elif mod_type == 'modify_random_line':
                # Modify a random line
                lines = content.split('\n')
                if lines:
                    line_idx = random.randrange(len(lines))
                    lines[line_idx] = self.generate_random_ascii_content(len(lines[line_idx]))
                    content = '\n'.join(lines)

            elif mod_type == 'delete_random_line':
                # Delete a random line
                lines = content.split('\n')
                if len(lines) > 1:
                    line_idx = random.randrange(len(lines))
                    lines.pop(line_idx)
                    content = '\n'.join(lines)

            elif mod_type == 'replace_words':
                # Replace random words
                words = content.split()
                if words:
                    num_replacements = min(random.randint(1, 5), len(words))
                    for _ in range(num_replacements):
                        word_idx = random.randrange(len(words))
                        words[word_idx] = self.generate_random_ascii_content(len(words[word_idx]))
                    content = ' '.join(words)

            # Write modified content back to file
            with open(filepath, 'w', encoding='ascii') as f:
                f.write(content)

            # Update file record
            new_hash = hashlib.sha256(content.encode('ascii')).hexdigest()
            self.file_records[filename] = {
                'original_hash': self.file_records[filename]['original_hash'],
                'current_hash': new_hash,
                'status': 'legitimately_modified',
                'modification_type': mod_type,
                'modification_time': datetime.now().isoformat()
            }

            self.legitimately_modified_files.append(filename)

        print(f"Legitimately modified {num_files_to_modify} files.")

    def perform_ransomware_simulations(self, percentage=20):
        """Simulate ransomware activity on a percentage of files"""
        # Only modify files that we created in this test run and haven't already modified
        available_files = [f for f in self.generated_files
                           if f not in self.legitimately_modified_files]

        num_files_to_encrypt = min(int(len(self.generated_files) * percentage / 100), len(available_files))
        if num_files_to_encrypt == 0:
            print("No files available for ransomware simulation.")
            return

        files_to_encrypt = random.sample(available_files, num_files_to_encrypt)

        print(f"Simulating ransomware activity on {num_files_to_encrypt} files...")

        for filename in files_to_encrypt:
            filepath = os.path.join(self.folder_path, filename)

            # Read current content
            with open(filepath, 'r', encoding='ascii') as f:
                content = f.read()

            # Choose a random encryption simulation type
            encryption_type = random.choice([
                'base64_full',
                'base64_partial',
                'xor_cipher',
                'character_substitution',
                'reverse_content',
                'file_corruption'
            ])

            if encryption_type == 'base64_full':
                # Full Base64 encoding - simulates full file encryption
                encoded = base64.b64encode(content.encode('ascii')).decode('ascii')
                modified_content = encoded

            elif encryption_type == 'base64_partial':
                # Partial Base64 encoding - simulates partial file encryption
                chunk_size = len(content) // 3
                start_pos = random.randint(0, max(1, len(content) - chunk_size))
                end_pos = start_pos + chunk_size

                prefix = content[:start_pos]
                to_encrypt = content[start_pos:end_pos]
                suffix = content[end_pos:]

                encrypted_part = base64.b64encode(to_encrypt.encode('ascii')).decode('ascii')
                modified_content = prefix + encrypted_part + suffix

            elif encryption_type == 'xor_cipher':
                # Simple XOR encryption with a random key
                key = random.randint(1, 255)
                modified_content = ''.join(chr(ord(c) ^ key) for c in content)
                # Ensure we stay within ASCII range
                modified_content = ''.join(c if ord(c) < 128 else chr(ord(c) % 128) for c in modified_content)

            elif encryption_type == 'character_substitution':
                # Substitution cipher - replace each character with another ASCII character
                char_map = {c: random.choice(string.printable) for c in string.printable}
                modified_content = ''.join(char_map.get(c, c) for c in content)

            elif encryption_type == 'reverse_content':
                # Simple transformation - reverse content
                modified_content = content[::-1]

            elif encryption_type == 'file_corruption':
                # Simulate corrupted file - replace random chunks with random data
                chunks = [content[i:i + 100] for i in range(0, len(content), 100)]
                corrupt_indices = random.sample(range(len(chunks)), min(3, len(chunks)))

                for idx in corrupt_indices:
                    chunks[idx] = self.generate_random_ascii_content(len(chunks[idx]))

                modified_content = ''.join(chunks)

            # Write modified content back to file
            with open(filepath, 'w', encoding='ascii') as f:
                f.write(modified_content)

            # Update file record
            new_hash = hashlib.sha256(modified_content.encode('ascii')).hexdigest()
            self.file_records[filename] = {
                'original_hash': self.file_records[filename]['original_hash'],
                'current_hash': new_hash,
                'status': 'ransomware_simulated',
                'encryption_type': encryption_type,
                'modification_time': datetime.now().isoformat()
            }

            self.encrypted_files.append(filename)

        print(f"Simulated ransomware activity on {num_files_to_encrypt} files.")

    def create_ground_truth_file(self):
        """Create a JSON file with the ground truth about file modifications"""
        truth_filename = f"ground_truth_{self.test_id}.json"
        truth_file = os.path.join(os.path.dirname(self.folder_path), truth_filename)

        truth_data = {
            'test_id': self.test_id,
            'test_time': datetime.now().isoformat(),
            'total_generated_files': len(self.generated_files),
            'legitimately_modified_files': self.legitimately_modified_files,
            'encrypted_files': self.encrypted_files,
            'file_details': self.file_records
        }

        with open(truth_file, 'w') as f:
            json.dump(truth_data, f, indent=4)

        print(f"Ground truth saved to {truth_file}")

        # Print summary
        print("\n--- Test Summary ---")
        print(f"Total new files generated: {len(self.generated_files)}")
        print(f"Legitimate modifications: {len(self.legitimately_modified_files)}")
        print(f"Ransomware simulations: {len(self.encrypted_files)}")
        print(
            f"Unmodified files: {len(self.generated_files) - len(self.legitimately_modified_files) - len(self.encrypted_files)}")

        return truth_file


def run_test():
    """Run the ransomware detection test"""
    tester = RansomwareDetectionTester(num_files=20)

    # Create test files
    tester.create_test_files()

    # Wait a moment to simulate time passing
    time.sleep(1)

    # Perform legitimate modifications (30% of files)
    tester.perform_legitimate_modifications(percentage=30)

    # Wait a moment to simulate time passing
    time.sleep(1)

    # Perform ransomware simulations (20% of files)
    tester.perform_ransomware_simulations(percentage=20)

    # Create ground truth file
    truth_file = tester.create_ground_truth_file()

    print(f"\nTest environment created successfully!")
    print(f"You can now run your ransomware detection tool on the '{tester.folder_path}' directory")
    print(f"and compare its results with the ground truth in '{truth_file}'")


if __name__ == "__main__":
    run_test()