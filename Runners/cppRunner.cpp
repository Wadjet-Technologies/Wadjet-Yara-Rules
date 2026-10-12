#include <iostream>
#include <string>
#include <yara.h>


// Callback function triggered whenever a rule matches during a scan
int scan_callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data) 
{
    if (message == CALLBACK_MSG_RULE_MATCHING) 
    {
        YR_RULE* rule = static_cast<YR_RULE*>(message_data);
        std::cout << "[🚨ALERT] Match detected! Rule identifier: " << rule->identifier << "\n";
    }
    return CALLBACK_CONTINUE;
}

int main() 
{
    // 1. Global library initialization (must run on the main thread)
    if (yr_initialize() != ERROR_SUCCESS) 
    {
        std::cerr << "[-] Failed to initialize libyara.\n";
        return 1;
    }

    YR_COMPILER* compiler = nullptr;
    YR_RULES* compiled_rules = nullptr;

    // 2. Create the compiler environment
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) 
    {
        std::cerr << "[-] Failed to create YARA compiler.\n";
        yr_finalize();
        return 1;
    }

    // Define a basic testing rule - Need to change this to import rules from folder
    std::string rule_source = R"(
        rule TargetDetection {
            strings:
                $magic_string = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
            condition:
                $magic_string
        }
    )";

    // 3. Compile the rule string into the compiler context
    if (yr_compiler_add_string(compiler, rule_source.c_str(), nullptr) != 0) 
    {
        std::cerr << "[-] Error compiling YARA rule text.\n";
        yr_compiler_destroy(compiler);
        yr_finalize();
        return 1;
    }

    // 4. Extract the executable rules package from the compiler
    if (yr_compiler_get_rules(compiler, &compiled_rules) != ERROR_SUCCESS) 
    {
        std::cerr << "[-] Failed to extract compiled rules container.\n";
        yr_compiler_destroy(compiler);
        yr_finalize();
        return 1;
    }

    // The compiler framework can now be cleanly disposed of
    yr_compiler_destroy(compiler);

    // Mock payload containing the targeted content
    std::string target_buffer = "Payload header data... EICAR-STANDARD-ANTIVIRUS-TEST-FILE! trailing artifacts...";

    std::cout << "[*] Starting memory scan...\n";

    // 5. Execute the evaluation pass against a live block of memory
    int scan_result = yr_rules_scan_mem(
        compiled_rules,
        reinterpret_cast<const uint8_t*>(target_buffer.data()),
        target_buffer.size(),
        0,              // Scan flags (e.g., SCAN_FLAGS_FAST_MODE)
        scan_callback,  // Matching hook function
        nullptr,        // Optional pointer to pass user-defined data objects to the callback
        0               // Timeout threshold in seconds (0 = infinite)
    );

    if (scan_result != ERROR_SUCCESS) 
    {
        std::cerr << "[-] Error executing target data scan. Code: " << scan_result << "\n";
    }

    // 6. Mandatory resource teardown and memory cleanup
    yr_rules_destroy(compiled_rules);
    yr_finalize();

    return 0;
}