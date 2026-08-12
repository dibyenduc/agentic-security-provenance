pragma circom 2.2.3;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

/*
 * Zero-Knowledge Agent State Verifier
 * 
 * This circuit proves that an Agent is authorized to transition 
 * from State A to State B (e.g., executing a sensitive Wasm tool)
 * WITHOUT revealing the enterprise's private policy rules or the 
 * exact private key of the IAM Role.
 */

template AgentIntentVerifier() {
    // Public Inputs (What the enterprise verifier sees)
    signal input agentRoleHash;       // Hash of the agent's IAM role
    signal input proposedActionHash;  // Hash of the tool the agent wants to execute
    
    // Private Inputs (What the agent holds locally, kept hidden)
    signal input privateIAMKey;       // The agent's private cryptographic key
    signal input policySecret;        // The enterprise policy secret mapped to this action
    
    // Output (Boolean: 1 if authorized, 0 if denied)
    signal output isAuthorized;

    // --- STEP 1: Verify the Agent's Identity ---
    // Prove that the private IAM key correctly hashes to the public agentRoleHash
    component identityHasher = Poseidon(1);
    identityHasher.inputs[0] <== privateIAMKey;
    
    component checkIdentity = IsEqual();
    checkIdentity.in[0] <== identityHasher.out;
    checkIdentity.in[1] <== agentRoleHash;
    
    // Enforce that the identity matches (Circuit fails here if fake key)
    checkIdentity.out === 1;

    // --- STEP 2: Verify the Policy Capability ---
    // Prove that the policy secret combined with the role authorizes the action
    component actionHasher = Poseidon(2);
    actionHasher.inputs[0] <== privateIAMKey;
    actionHasher.inputs[1] <== policySecret;
    
    component checkAction = IsEqual();
    checkAction.in[0] <== actionHasher.out;
    checkAction.in[1] <== proposedActionHash;
    
    // Enforce that the action is authorized
    checkAction.out === 1;
    
    // If both checks pass, output 1 (True)
    isAuthorized <== 1;
}

// Instantiate the component
component main = AgentIntentVerifier();
