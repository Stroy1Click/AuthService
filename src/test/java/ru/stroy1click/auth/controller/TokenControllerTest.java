package ru.stroy1click.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import ru.stroy1click.auth.dto.RefreshTokenRequest;
import ru.stroy1click.auth.filter.JwtAuthFilter;
import ru.stroy1click.auth.service.RefreshTokenService;

import static org.junit.jupiter.api.Assertions.assertEquals;

@AutoConfigureMockMvc(addFilters = false)
@WebMvcTest(controllers = TokenController.class)
public class TokenControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private RefreshTokenService refreshTokenService;

    @MockitoBean
    private JwtAuthFilter jwtAuthFilter;

    @Test
    public void refreshAccessToken_WhenTokenIsBlank_ShouldThrowValidationException() throws Exception {
        //Arrange
        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest();

        RequestBuilder requestBuilder = MockMvcRequestBuilders.post("/api/v1/tokens/access")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(refreshTokenRequest));

        //Act
        MvcResult result = this.mockMvc.perform(requestBuilder).andReturn();
        String string = result.getResponse().getContentAsString();
        ProblemDetail problemDetail = new ObjectMapper().readValue(string, ProblemDetail.class);
        int status = result.getResponse().getStatus();

        //Act
        assertEquals(400, status);
        assertEquals("Refresh token не может быть пустым", problemDetail.getDetail());
    }

    @Test
    public void refreshToken_WhenTokenIsBlank_ShouldThrowValidationException() throws Exception {
        //Arrange
        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest();

        RequestBuilder requestBuilder = MockMvcRequestBuilders.patch("/api/v1/tokens/refresh-token")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(refreshTokenRequest));

        //Act
        MvcResult result = this.mockMvc.perform(requestBuilder).andReturn();
        String string = result.getResponse().getContentAsString();
        ProblemDetail problemDetail = new ObjectMapper().readValue(string, ProblemDetail.class);
        int status = result.getResponse().getStatus();

        //Act
        assertEquals(400, status);
        assertEquals("Refresh token не может быть пустым", problemDetail.getDetail());
    }

    @Test
    public void refreshAccessToken_WhenTokenLengthIsInvalid_ShouldThrowValidationException() throws Exception {
        //Arrange
        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest("12345");

        RequestBuilder requestBuilder = MockMvcRequestBuilders.post("/api/v1/tokens/access")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(refreshTokenRequest));

        //Act
        MvcResult result = this.mockMvc.perform(requestBuilder).andReturn();
        String string = result.getResponse().getContentAsString();
        ProblemDetail problemDetail = new ObjectMapper().readValue(string, ProblemDetail.class);
        int status = result.getResponse().getStatus();

        //Act
        assertEquals(400, status);
        assertEquals("Длина токена должна составлять 36 символов", problemDetail.getDetail());
    }

    @Test
    public void refreshToken_WhenTokenLengthIsInvalid_ShouldThrowValidationException() throws Exception {
        //Arrange
        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest("12345");

        RequestBuilder requestBuilder = MockMvcRequestBuilders.patch("/api/v1/tokens/refresh-token")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(refreshTokenRequest));

        //Act
        MvcResult result = this.mockMvc.perform(requestBuilder).andReturn();
        String string = result.getResponse().getContentAsString();
        ProblemDetail problemDetail = new ObjectMapper().readValue(string, ProblemDetail.class);
        int status = result.getResponse().getStatus();

        //Act
        assertEquals(400, status);
        assertEquals("Длина токена должна составлять 36 символов", problemDetail.getDetail());
    }
}
