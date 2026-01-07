package com.seoeunjin.api.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.RequestBody;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;
import io.swagger.v3.oas.models.servers.Server;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Bean
    @Primary
    public OpenAPI customOpenAPI() {
        OpenAPI openAPI = new OpenAPI()
                .info(new Info()
                        .title("Seoeunjin.com Gateway API")
                        .version("1.0.0")
                        .description("API Gateway for Seoeunjin.com Services")
                        .contact(new Contact()
                                .name("Seoeunjin.com")
                                .email("support@seoeunjin.com")))
                .servers(List.of(
                        new Server().url("api.seoeunjin.com").description("Local Development Server"),
                        new Server().url("http://api.seoeunjin.com").description("Production Server")));

        // Gateway 라우트 경로 추가
        io.swagger.v3.oas.models.Paths paths = new io.swagger.v3.oas.models.Paths();

        // Auth Service Routes
        addPath(paths, "/api/auth", "인증 서비스", "Authentication Service API");
        addPath(paths, "/oauth2/kakao", "카카오 OAuth", "Kakao OAuth2 API");

        // User Service Routes
        addPath(paths, "/api/users", "사용자 서비스", "User Service API");

        // ML Service Routes
        addPath(paths, "/api/ml", "머신러닝 서비스", "Machine Learning Service API");

        // Transformer Service Routes - 실제 엔드포인트에 맞게 메서드 지정
        // POST /koelectra/sentiment - 단일 감성 분석
        addSentimentPostPath(paths, "/api/transformer/koelectra/sentiment", "KoELECTRA 감성 분석",
                "KoELECTRA Sentiment Analysis API");

        // POST /koelectra/sentiment/batch - 배치 감성 분석
        addBatchSentimentPostPath(paths, "/api/transformer/koelectra/sentiment/batch", "KoELECTRA 배치 감성 분석",
                "KoELECTRA Batch Sentiment Analysis API");

        // GET /koelectra/model/info - 모델 정보
        addGetPath(paths, "/api/transformer/koelectra/model/info", "KoELECTRA 모델 정보", "KoELECTRA Model Info API");

        // GET /koelectra/health - 헬스 체크
        addGetPath(paths, "/api/transformer/koelectra/health", "KoELECTRA 헬스 체크", "KoELECTRA Health Check API");

        openAPI.setPaths(paths);
        return openAPI;
    }

    @Bean
    public GroupedOpenApi gatewayApi() {
        return GroupedOpenApi.builder()
                .group("gateway")
                .displayName("Gateway API")
                .pathsToMatch("/api/**", "/oauth2/**")
                .build();
    }

    @Bean
    public GroupedOpenApi transformerServiceApi() {
        return GroupedOpenApi.builder()
                .group("transformerservice")
                .displayName("Transformer Service API")
                .pathsToMatch("/api/transformer/**")
                .build();
    }

    private void addPath(io.swagger.v3.oas.models.Paths paths, String path, String summary, String description) {
        PathItem pathItem = new PathItem();

        // GET operation
        Operation getOp = new Operation();
        getOp.setSummary(summary + " - GET");
        getOp.setDescription(description);
        getOp.setOperationId("get" + sanitizeOperationId(path));
        getOp.setResponses(createDefaultResponses());
        pathItem.setGet(getOp);

        // POST operation
        Operation postOp = new Operation();
        postOp.setSummary(summary + " - POST");
        postOp.setDescription(description);
        postOp.setOperationId("post" + sanitizeOperationId(path));
        postOp.setResponses(createDefaultResponses());
        pathItem.setPost(postOp);

        // PUT operation
        Operation putOp = new Operation();
        putOp.setSummary(summary + " - PUT");
        putOp.setDescription(description);
        putOp.setOperationId("put" + sanitizeOperationId(path));
        putOp.setResponses(createDefaultResponses());
        pathItem.setPut(putOp);

        // DELETE operation
        Operation deleteOp = new Operation();
        deleteOp.setSummary(summary + " - DELETE");
        deleteOp.setDescription(description);
        deleteOp.setOperationId("delete" + sanitizeOperationId(path));
        deleteOp.setResponses(createDefaultResponses());
        pathItem.setDelete(deleteOp);

        paths.addPathItem(path, pathItem);
    }

    private void addGetPath(io.swagger.v3.oas.models.Paths paths, String path, String summary, String description) {
        PathItem pathItem = new PathItem();
        Operation getOp = new Operation();
        getOp.setSummary(summary);
        getOp.setDescription(description);
        getOp.setOperationId("get" + sanitizeOperationId(path));
        getOp.setResponses(createDefaultResponses());
        pathItem.setGet(getOp);
        paths.addPathItem(path, pathItem);
    }

    private void addSentimentPostPath(io.swagger.v3.oas.models.Paths paths, String path, String summary,
            String description) {
        PathItem pathItem = new PathItem();
        Operation postOp = new Operation();
        postOp.setSummary(summary);
        postOp.setDescription(description);
        postOp.setOperationId("post" + sanitizeOperationId(path));

        // Request Body 스키마 정의
        Schema<?> requestSchema = new Schema<>()
                .type("object")
                .addProperty("text", new Schema<>()
                        .type("string")
                        .description("분석할 텍스트")
                        .minLength(1)
                        .maxLength(2000)
                        .example("이 영화 정말 재미있었어요! 강력 추천합니다."));
        requestSchema.setRequired(List.of("text"));

        RequestBody requestBody = new RequestBody()
                .required(true)
                .content(new Content()
                        .addMediaType("application/json", new MediaType()
                                .schema(requestSchema)));
        postOp.setRequestBody(requestBody);

        // Response 스키마 정의
        Schema<?> responseSchema = new Schema<>()
                .type("object")
                .addProperty("text", new Schema<>().type("string"))
                .addProperty("sentiment", new Schema<>().type("string"))
                .addProperty("confidence", new Schema<>().type("object"))
                .addProperty("score", new Schema<>().type("number").format("float"));

        ApiResponses responses = new ApiResponses();
        responses.addApiResponse("200", new ApiResponse()
                .description("Success")
                .content(new Content()
                        .addMediaType("application/json", new MediaType()
                                .schema(responseSchema))));
        responses.addApiResponse("400", new ApiResponse().description("Bad Request"));
        responses.addApiResponse("422", new ApiResponse().description("Unprocessable Entity"));
        responses.addApiResponse("500", new ApiResponse().description("Internal Server Error"));
        postOp.setResponses(responses);

        pathItem.setPost(postOp);
        paths.addPathItem(path, pathItem);
    }

    private void addBatchSentimentPostPath(io.swagger.v3.oas.models.Paths paths, String path, String summary,
            String description) {
        PathItem pathItem = new PathItem();
        Operation postOp = new Operation();
        postOp.setSummary(summary);
        postOp.setDescription(description);
        postOp.setOperationId("post" + sanitizeOperationId(path));

        // Request Body 스키마 정의
        Schema<?> textsProperty = new Schema<>()
                .type("array")
                .items(new Schema<>().type("string"))
                .description("분석할 텍스트 리스트")
                .minItems(1)
                .maxItems(100);

        Schema<?> requestSchema = new Schema<>()
                .type("object")
                .addProperty("texts", textsProperty);
        requestSchema.setRequired(List.of("texts"));

        RequestBody requestBody = new RequestBody()
                .required(true)
                .content(new Content()
                        .addMediaType("application/json", new MediaType()
                                .schema(requestSchema)));
        postOp.setRequestBody(requestBody);

        // Response 스키마 정의
        Schema<?> sentimentResultSchema = new Schema<>()
                .type("object")
                .addProperty("text", new Schema<>().type("string"))
                .addProperty("sentiment", new Schema<>().type("string"))
                .addProperty("confidence", new Schema<>().type("object"))
                .addProperty("score", new Schema<>().type("number").format("float"));

        Schema<?> responseSchema = new Schema<>()
                .type("object")
                .addProperty("results", new Schema<>()
                        .type("array")
                        .items(sentimentResultSchema))
                .addProperty("total", new Schema<>().type("integer"));

        ApiResponses responses = new ApiResponses();
        responses.addApiResponse("200", new ApiResponse()
                .description("Success")
                .content(new Content()
                        .addMediaType("application/json", new MediaType()
                                .schema(responseSchema))));
        responses.addApiResponse("400", new ApiResponse().description("Bad Request"));
        responses.addApiResponse("422", new ApiResponse().description("Unprocessable Entity"));
        responses.addApiResponse("500", new ApiResponse().description("Internal Server Error"));
        postOp.setResponses(responses);

        pathItem.setPost(postOp);
        paths.addPathItem(path, pathItem);
    }

    private String sanitizeOperationId(String path) {
        return path.replace("/", "_")
                .replace("-", "_")
                .replace("{", "")
                .replace("}", "");
    }

    private ApiResponses createDefaultResponses() {
        ApiResponses responses = new ApiResponses();
        responses.addApiResponse("200", new ApiResponse().description("Success"));
        responses.addApiResponse("400", new ApiResponse().description("Bad Request"));
        responses.addApiResponse("401", new ApiResponse().description("Unauthorized"));
        responses.addApiResponse("404", new ApiResponse().description("Not Found"));
        responses.addApiResponse("500", new ApiResponse().description("Internal Server Error"));
        return responses;
    }
}
