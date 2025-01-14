package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	openai "github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	excel "github.com/xuri/excelize/v2"
)

type DefenderAssessment struct {
	NameID     string `json:"name"`
	Properties struct {
		ResourceDetails struct {
			ResourceName string `json:"ResourceName"`
			ResourceID   string `json:"NativeResourceId"`
		}
		DisplayName string `json:"displayName"`
		Status      struct {
			Code string `json:"code"`
		}
	}
}
type AssessmentMetadata struct {
	NameID     string `json:"name"`
	Properties struct {
		DisplayName string `json:"displayName"`
		Description string `json:"description"`
		Remediation string `json:"remediationDescription"`
		Severity    string `json:"severity"`
	}
}
type Recommendation struct {
	NameID            string
	DisplayName       string
	Description       string
	Severity          string
	AffectedResources []string
	Remediation       string
	Context           string
}
type AssessmentResponse struct {
	Vulnerabilities []DefenderAssessment `json:"value"`
}
type MetadataResponse struct {
	Vulnerabilities []AssessmentMetadata `json:"value"`
}

func getCred(scope string) (*azcore.AccessToken, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		// Log the error and return it
		fmt.Println("Error creating credential in getCred:", err)
		return nil, err
	}

	// Use the default az credential to get a token.
	aadToken, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{scope}})
	if err != nil {
		fmt.Println("Error grabbing token:", err)
		return nil, err
	}

	return &aadToken, nil
}

func makeRequest[T any](apiUrl string, token *azcore.AccessToken) ([]T, error) {
	var allResults []T
	var url = apiUrl

	for url != "" {
		// Create a new GET request
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("error creating request: %w", err)
		}

		// Add the token in the request header
		req.Header.Add("Authorization", "Bearer "+token.Token)

		// Make the request
		client := &http.Client{}
		res, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("error making request: %w", err)
		}
		defer res.Body.Close()

		// Read the response body
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, fmt.Errorf("error reading response body: %w", err)
		}

		// Handle the response generically
		var response struct {
			Value    []T    `json:"value"`
			NextLink string `json:"nextLink"`
		}

		// Unmarshal the response into the generic structure
		err = json.Unmarshal(body, &response)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling response: %w", err)
		}

		// Append the results to the final slice
		allResults = append(allResults, response.Value...)

		// Update the URL for the next page
		url = response.NextLink
	}

	return allResults, nil
}
func fetchAssessments(apiUrl string, token *azcore.AccessToken) ([]DefenderAssessment, error) {
	// Fetch all assessments
	assessments, err := makeRequest[DefenderAssessment](apiUrl, token)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch assessments: %w", err)
	}
	return assessments, nil
}
func fetchMetadata(apiUrl string, token *azcore.AccessToken) ([]AssessmentMetadata, error) {
	// Fetch all metadata
	metadata, err := makeRequest[AssessmentMetadata](apiUrl, token)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata: %w", err)
	}
	return metadata, nil
}

func getOpenAiKey() string {
	var key string
	var choice string
	var envName string

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("Get OpenAI API key. Please type in your choice: 'Enter Key' or 'Env Variable': ")
		choice, _ = reader.ReadString('\n') // Read input until newline
		choice = strings.TrimSpace(choice)  // Trim newline and any spaces

		if strings.EqualFold(choice, "Enter Key") {
			fmt.Print("Enter Key: ")
			key, _ = reader.ReadString('\n') // Read the key input
			key = strings.TrimSpace(key)     // Trim newline and any spaces
			if key != "" {
				return key
			}
			fmt.Println("API key cannot be empty. Please try again.")
		} else if strings.EqualFold(choice, "Env Variable") {
			fmt.Print("Enter name of env variable: ")
			envName, _ = reader.ReadString('\n') // Read the env variable name
			envName = strings.TrimSpace(envName)
			fmt.Println("Grabbing API key....")
			key = os.Getenv(envName)

			if key != "" {
				return key
			}
			fmt.Println("API key not found! Ensure the environment variable is set correctly and try again.")
		} else {
			fmt.Println("Invalid input. Please choose 'Enter Key' or 'Env Variable'.")
		}
	}
}

func getScope() (string, bool) {
	var scope string
	var subscriptionid string
	var managementgroup string
	var scopeString string

	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("What scope do you want the vulnerability data to be on? Type 'subscription' or 'managementgroup': ")
		scope, _ = reader.ReadString('\n') // Read input until newline
		scope = strings.TrimSpace(scope)   // Trim newline and any spaces

		if strings.EqualFold(scope, "subscription") {
			fmt.Print("What is your subscription ID: ")
			subscriptionid, _ = reader.ReadString('\n')        // Read the subscription ID
			subscriptionid = strings.TrimSpace(subscriptionid) //Remove space
			if subscriptionid != "" {
				scopeString = fmt.Sprintf("subscriptions/%v", subscriptionid) //Formate string
				return scopeString, true
			}
			fmt.Println("Subscription ID cannot be empty. Please try again.")
		} else if strings.EqualFold(scope, "managementgroup") {
			fmt.Print("What is your management group name: ")
			managementgroup, _ = reader.ReadString('\n')         // Read the management group name
			managementgroup = strings.TrimSpace(managementgroup) //Remove space
			if managementgroup != "" {
				scopeString = fmt.Sprintf("providers/Microsoft.Management/managementGroups/%v", managementgroup) //Format string
				return scopeString, false
			}
			fmt.Println("Management group name cannot be empty. Please try again.")
		} else {
			fmt.Println("Invalid input. Please choose 'subscription' or 'managementgroup'.")
		}
	}
}

func createRecommendation(assessments []DefenderAssessment, metadatas []AssessmentMetadata) []Recommendation {
	var filteredAssessments []DefenderAssessment
	existingRecommendations := make(map[string]*Recommendation)

	//Filter the slice so it is just the unhealthy assessments
	for _, assessment := range assessments {
		// Check if the assessment is "Unhealthy"; if so, keep it
		if assessment.Properties.Status.Code == "Unhealthy" {
			filteredAssessments = append(filteredAssessments, assessment)
		}
	}

	// Loop through each filtered assessment
	for _, filteredAssessment := range filteredAssessments {
		// Check if recommendation for this NameID already exists
		if recommendation, found := existingRecommendations[filteredAssessment.NameID]; found {
			// Append the resource name to the existing recommendation
			recommendation.AffectedResources = append(recommendation.AffectedResources, filteredAssessment.Properties.ResourceDetails.ResourceName)
		} else {
			// Create a new recommendation since it doesn't exist
			newRecommendation := Recommendation{
				NameID:            filteredAssessment.NameID,
				DisplayName:       filteredAssessment.Properties.DisplayName, // Use DisplayName from filteredAssessment
				Description:       "Unknown",
				Severity:          "Unknown", // Set unkown as default.
				AffectedResources: []string{filteredAssessment.Properties.ResourceDetails.ResourceName},
				Remediation:       "Unknown", // You can leave remediation empty for now
				Context:           "Unknown", // Leave empty metadata will will and if it doesnt AI will
			}
			// Add the new recommendation to the map
			existingRecommendations[filteredAssessment.NameID] = &newRecommendation
		}
	}
	for _, metadata := range metadatas { // Loop through all the metadatas and if the nameid is already created update the struct fields.
		if recommendationid, found := existingRecommendations[metadata.NameID]; found {
			recommendationid.Description = metadata.Properties.Description
			recommendationid.Severity = metadata.Properties.Severity
			recommendationid.Remediation = metadata.Properties.Remediation
		}
	}

	var recommendations []Recommendation
	for _, recommendation := range existingRecommendations { //Convert back to slice to return
		recommendations = append(recommendations, *recommendation)
	}

	return recommendations
}

func aiEnrich(apiKey string, recommendation *Recommendation, wg *sync.WaitGroup, ch chan<- *Recommendation) {

	defer wg.Done() //Run this after func is done to subtract wg addition to goroutine

	client := openai.NewClient(
		option.WithAPIKey(apiKey))
	ctx := context.Background()

	vulnerabilityName := recommendation.DisplayName
	description := recommendation.Description
	remediation := recommendation.Remediation
	//Give prompt to the AI so it knows how it should be answering.
	prompt := `
	The following is a Azure vulnerability report. You are a expert in Azure cloud security and need to provide additonal info to your team, so try and enrich it with additional details:
	The sections should be named **Explanation of the Vulnerability:**, **Remediation Steps:**, **Context about the Impact of the Vulnerability:**
	- Provide an expanded explanation of the vulnerability.
	- Suggest remediation steps, but keep it kinda short because it needs to be done on alot of vulnerabilities.
	- Provide context about the impact of the vulnerability.
	- If you are given "unknown", create the three keys regardless with your own information. Do not leave anything blank.

	Vulnerability Name: ` + vulnerabilityName + `
	Description: ` + description + `
	Remediation: ` + remediation + `

	Response:
	`

	//Make the request to the AI
	completion, err := client.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{
		Messages: openai.F([]openai.ChatCompletionMessageParamUnion{
			openai.UserMessage(prompt),
		}),
		Seed:  openai.Int(1),
		Model: openai.F(openai.ChatModelGPT4o),
	})
	if err != nil {
		panic(err)
	}

	response := completion.Choices[0].Message.Content //Grab response
	// Parse the response into variables
	explanation, remediation, context := parseAIResponse(response) //Parse the response to get the needed variables and then update the stuct object.
	recommendation.Description = explanation
	recommendation.Remediation = remediation
	recommendation.Context = context

	ch <- recommendation
}

/*
This is the func that does not use goroutines, you can test it to see the speed difference.
func aiEnrich(recommendation Recommendation) (string, string, string) {

	client := openai.NewClient(
		option.WithAPIKey("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"))
	ctx := context.Background()

	vulnerabilityName := recommendation.DisplayName
	description := recommendation.Description
	remediation := recommendation.Remediation
	prompt := `
	The following is a vulnerability report. You are a cloud security engineer and need to provide additonal info to your team, so try and enrich it with additional details:
	The sections should be named **Explanation of the Vulnerability:**, **Remediation Steps:**, **Context about the Impact of the Vulnerability:**
	- Provide an expanded explanation of the vulnerability.
	- Suggest remediation steps, but keep it kinda short because it needs to be done on alot of vulnerabilities.
	- Provide context about the impact of the vulnerability.
	- If you are given "unknown", create the three keys regardless with your own information.

	Vulnerability Name: ` + vulnerabilityName + `
	Description: ` + description + `
	Remediation: ` + remediation + `

	Response:
	`

	//print("> ")
	//println(prompt)
	//println()

	completion, err := client.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{
		Messages: openai.F([]openai.ChatCompletionMessageParamUnion{
			openai.UserMessage(prompt),
		}),
		Seed:  openai.Int(1),
		Model: openai.F(openai.ChatModelGPT4o),
	})
	if err != nil {
		panic(err)
	}

	response := completion.Choices[0].Message.Content
	// Parse the response into variables
	explanation, remediation, context := parseAIResponse(response)

	return explanation, remediation, context
}
*/

// Function to parse the AI response into sections
func parseAIResponse(response string) (string, string, string) {
	// Define markers
	explanationMarker := "**Explanation of the Vulnerability:**"
	remediationMarker := "**Remediation Steps:**"
	contextMarker := "**Context about the Impact of the Vulnerability:**"

	// Find each section using the markers
	explanationStart := strings.Index(response, explanationMarker)
	remediationStart := strings.Index(response, remediationMarker)
	contextStart := strings.Index(response, contextMarker)

	// Extract the content for each section
	explanation := ""
	remediation := ""
	context := ""

	//This whole section checks to see if the start exist. There should be three starts from the AI if it returns
	// 3 sections with the exact string as we told it to in the prompt. If it doesn't have it the start for them would be -1
	// because they don't exist. So lets look at an example.
	/*
		**Explanation of the Vulnerability:** Improper input validation can lead to SQL injection attacks.
		**Remediation Steps:** Use parameterized queries and validate all inputs.
		**Context about the Impact of the Vulnerability:** This vulnerability can lead to data breaches.

		The very fist row is the explanation marker. So if it exist the explanantion start would mark its position in the response which would be 0.
		If would check if the next start exist because if it does that is going to be the end of the explanantion string. If it exist
		it is going to pull the data from explanation start which is 0 + the length of the marker **Explanation of the Vulnerability:**
		which lets say is 15 to the start of the next marker which is the remediation start. So it is going to slice [15:60] from the whole response string
		that got return from the AI. The whole explanation response meat is in between 15:30 index in the response string.
	*/
	if explanationStart != -1 {
		if remediationStart != -1 {
			explanation = strings.TrimSpace(response[explanationStart+len(explanationMarker) : remediationStart])
		} else if contextStart != -1 {
			explanation = strings.TrimSpace(response[explanationStart+len(explanationMarker) : contextStart])
		} else {
			explanation = strings.TrimSpace(response[explanationStart+len(explanationMarker):])
		}
	}

	if remediationStart != -1 {
		if contextStart != -1 {
			remediation = strings.TrimSpace(response[remediationStart+len(remediationMarker) : contextStart])
		} else {
			remediation = strings.TrimSpace(response[remediationStart+len(remediationMarker):])
		}
	}

	if contextStart != -1 {
		context = strings.TrimSpace(response[contextStart+len(contextMarker):])
	}

	return explanation, remediation, context
}

// Call aiEnrich for each instance of recommendation and use the data from AI in the struct fields.
// Retired because now the aiEnric is going to update the recommendations directly in its func.
/*
func updateRecommendations(recommendations *[]Recommendation) {
	for i, _ := range *recommendations {
		explanation, remediation, context := aiEnrich((*recommendations)[i])
		(*recommendations)[i].Remediation = remediation
		(*recommendations)[i].Context = context
		(*recommendations)[i].Description = explanation
	}
}
*/
func exportToExcel(recommendations []Recommendation, fileName string) error {
	f := excel.NewFile()
	sheetName := "Recommendations"
	f.SetSheetName(f.GetSheetName(0), sheetName)

	headers := []string{"DisplayName", "Description", "Severity", "AffectedResources", "Remediation", "Context"}

	// Write headers
	for i, header := range headers {
		col := fmt.Sprintf("%c", 'A'+i) // Convert index to a column letter
		cell := fmt.Sprintf("%s1", col)
		if err := f.SetCellValue(sheetName, cell, header); err != nil {
			return fmt.Errorf("failed to set header cell %s: %w", cell, err)
		}
	}

	// Write data rows
	for rowIndex, rec := range recommendations {
		row := rowIndex + 2 // Start from row 2 (after headers)
		//Loop through and write the data one row at a time
		if err := f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), rec.DisplayName); err != nil {
			return err
		}
		if err := f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), rec.Description); err != nil {
			return err
		}
		if err := f.SetCellValue(sheetName, fmt.Sprintf("C%d", row), rec.Severity); err != nil {
			return err
		}
		if err := f.SetCellValue(sheetName, fmt.Sprintf("D%d", row), strings.Join(rec.AffectedResources, ", ")); err != nil {
			return err
		}
		if err := f.SetCellValue(sheetName, fmt.Sprintf("E%d", row), rec.Remediation); err != nil {
			return err
		}
		if err := f.SetCellValue(sheetName, fmt.Sprintf("F%d", row), rec.Context); err != nil {
			return err
		}
	}

	// Save the file. You can change the path in teh fileName up top this func
	if err := f.SaveAs(fileName); err != nil {
		return fmt.Errorf("failed to save Excel file: %w", err)
	}

	fmt.Printf("File successfully saved as: %s\n", fileName)
	return nil
}

func main() {
	//Run the program
	aadToken, err := getCred("https://management.azure.com/.default")
	if err != nil {
		fmt.Println("Error grabbing management AAD token:", err)
		return
	}
	apiKey := getOpenAiKey()
	fmt.Println(apiKey)
	scopeString, sub := getScope()
	var assessmentApi string

	if sub {
		// For subscription scope
		assessmentApi = fmt.Sprintf("https://management.azure.com/%v/providers/Microsoft.Security/assessments?api-version=2021-06-01", scopeString)
	} else {
		// For management group scope
		assessmentApi = fmt.Sprintf("https://management.azure.com/%v/providers/Microsoft.Security/assessments?api-version=2021-06-01", scopeString)
	}
	//fmt.Println(assessmentApi)
	metadataApi := "https://management.azure.com/providers/Microsoft.Security/assessmentMetadata?api-version=2021-06-01"

	start := time.Now()
	fmt.Println("Fetching vulnerability data.....")

	assessments, err := fetchAssessments(assessmentApi, aadToken)
	if err != nil {
		fmt.Println("Error grabbing vulnerabilities:", err)
	}
	assessmentMetadata, err := fetchMetadata(metadataApi, aadToken)
	if err != nil {
		fmt.Println("Error grabbing metadata:", err)
	}

	// Print the raw body for debugging
	//fmt.Println("Response Body:", string(assessmentBody))
	// Print the raw body for debugging
	//fmt.Println("Response Body:", string(metadataBody))

	// Unmarshal the response into the two response structs
	//var assessmentResponse AssessmentResponse
	//var metadataResponse MetadataResponse
	/*
		err = json.Unmarshal(assessmentBody, &assessmentResponse)
		if err != nil {
			fmt.Println("Error unmarshalling response:", err)
			return
		}
		err = json.Unmarshal(metadataBody, &metadataResponse)
		if err != nil {
			fmt.Println("Error unmarshalling response:", err)
			return
		}
	*/

	//Create the recommendation slice
	recommendations := createRecommendation(assessments, assessmentMetadata)

	//updateRecommendations(&recommendations)

	// Create goroutines, channel, and wg
	//Pass these into the aiEnrich so we can run multiple request at the same time
	// Note depending on your API tier and the amount of recommendations you have,
	// you may need to throttle the go routines by using a time based ticker, or a semaphore throttle.
	var wg sync.WaitGroup
	ch := make(chan *Recommendation)
	fmt.Println("Enriching the vulnerability data with AI.....")

	for i := range recommendations {
		wg.Add(1)
		go aiEnrich(apiKey, &recommendations[i], &wg, ch)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	var enrichedRecommendations []Recommendation
	for enrichedRecommendation := range ch {
		enrichedRecommendations = append(enrichedRecommendations, *enrichedRecommendation)
	}

	fmt.Printf("Exporting to excel document.....")
	err = exportToExcel(enrichedRecommendations, "DefenderRecommendationTest.xlsx")
	if err != nil {
		fmt.Println("Error creating excel file:", err)
	}
	elapsed := time.Since(start)
	fmt.Printf("Program complete. Total execution time: %s\n", elapsed)

}
