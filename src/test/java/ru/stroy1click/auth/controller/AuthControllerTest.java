package ru.stroy1click.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.*;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import ru.stroy1click.auth.dto.AuthRequest;
import ru.stroy1click.auth.dto.Role;
import ru.stroy1click.auth.dto.UserDto;
import ru.stroy1click.auth.filter.JwtAuthFilter;
import ru.stroy1click.auth.service.AuthService;
import ru.stroy1click.auth.service.RefreshTokenService;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@AutoConfigureMockMvc(addFilters = false)
@WebMvcTest(controllers = AuthController.class)
public class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private RefreshTokenService refreshTokenService;

    @MockitoBean
    private JwtAuthFilter jwtAuthFilter;

    @Test
    public void registration_WhenUserDtoFirstNameIsBlank_ShouldThrowValidationException() throws Exception {
        //Arrange
        UserDto userDto = UserDto.builder()
                .firstName("")
                .lastName("Thompson")
                .email("kate_thompson3@gmail.com")
                .password("password123")
                .isEmailConfirmed(false)
                .role(Role.ROLE_USER)
                .build();

        RequestBuilder requestBuilder = MockMvcRequestBuilders.post("/api/v1/auth/registration")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(userDto));

        //Act
        MvcResult result = this.mockMvc.perform(requestBuilder).andReturn();
        String string = result.getResponse().getContentAsString();
        ProblemDetail problemDetail = new ObjectMapper().readValue(string, ProblemDetail.class);
        int status = result.getResponse().getStatus();

        //Act
        assertEquals(400, status);
        assertEquals("Ошибка валидации", problemDetail.getTitle());
    }

    @Test
    public void registration_WhenUserDtoFirstNameIsTooShort_ShouldThrowValidationException() throws Exception {
        //Arrange
        UserDto userDto = UserDto.builder()
                .firstName("F")
                .lastName("Thompson")
                .email("kate_thompson3@gmail.com")
                .password("password123")
                .isEmailConfirmed(false)
                .role(Role.ROLE_USER)
                .build();

        RequestBuilder requestBuilder = MockMvcRequestBuilders.post("/api/v1/auth/registration")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(userDto));

        //Act
        MvcResult result = this.mockMvc.perform(requestBuilder).andReturn();
        String string = result.getResponse().getContentAsString();
        ProblemDetail problemDetail = new ObjectMapper().readValue(string, ProblemDetail.class);
        int status = result.getResponse().getStatus();

        //Act
        assertEquals(400, status);
        assertEquals("Минимальная длина имени составляет 2 символа, максимальная - 30 символов", problemDetail.getDetail());
    }

    @Test
    public void registration_WhenUserDtoFirstNameIsTooLong_ShouldThrowValidationException() throws Exception {
        //Arrange
        UserDto userDto = UserDto.builder()
                .firstName("nsjdfnshjdfnsdhfbshdflbsdflhbfiubwifbsdfjhsdsldfbhsdflsndfsfmsdffvnjfdvfjdvkndjkfvnkdlfvhjdnfvbhldfvdfsvdfv")
                .lastName("Thompson")
                .email("kate_thompson3@gmail.com")
                .password("password123")
                .isEmailConfirmed(false)
                .role(Role.ROLE_USER)
                .build();

        RequestBuilder requestBuilder = MockMvcRequestBuilders.post("/api/v1/auth/registration")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(userDto));

        //Act
        MvcResult result = this.mockMvc.perform(requestBuilder).andReturn();
        String string = result.getResponse().getContentAsString();
        ProblemDetail problemDetail = new ObjectMapper().readValue(string, ProblemDetail.class);
        int status = result.getResponse().getStatus();

        //Act
        assertEquals(400, status);
        assertEquals("Минимальная длина имени составляет 2 символа, максимальная - 30 символов", problemDetail.getDetail());
    }

    @Test
    public void registration_WhenUserDtoLastNameIsBlank_ShouldThrowValidationException() throws Exception {
        //Arrange
        UserDto userDto = UserDto.builder()
                .firstName("FirstName")
                .lastName("")
                .email("kate_thompson3@gmail.com")
                .password("password123")
                .isEmailConfirmed(false)
                .role(Role.ROLE_USER)
                .build();

        RequestBuilder requestBuilder = MockMvcRequestBuilders.post("/api/v1/auth/registration")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(userDto));

        //Act
        MvcResult result = this.mockMvc.perform(requestBuilder).andReturn();
        String string = result.getResponse().getContentAsString();
        ProblemDetail problemDetail = new ObjectMapper().readValue(string, ProblemDetail.class);
        int status = result.getResponse().getStatus();

        //Act
        assertEquals(400, status);
        assertEquals("Ошибка валидации", problemDetail.getTitle());
    }

    @Test
    public void registration_WhenUserDtoLastNameIsTooShort_ShouldThrowValidationException() throws Exception {
        //Arrange
        UserDto userDto = UserDto.builder()
                .firstName("FirstName")
                .lastName("T")
                .email("kate_thompson3@gmail.com")
                .password("password123")
                .isEmailConfirmed(false)
                .role(Role.ROLE_USER)
                .build();

        RequestBuilder requestBuilder = MockMvcRequestBuilders.post("/api/v1/auth/registration")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(userDto));

        //Act
        MvcResult result = this.mockMvc.perform(requestBuilder).andReturn();
        String string = result.getResponse().getContentAsString();
        ProblemDetail problemDetail = new ObjectMapper().readValue(string, ProblemDetail.class);
        int status = result.getResponse().getStatus();

        //Act
        assertEquals(400, status);
        assertEquals("Минимальная длина фамилии составляет 2 символа, максимальная - 30 символов", problemDetail.getDetail());
    }

    @Test
    public void registration_WhenUserDtoLastNameIsTooLong_ShouldThrowValidationException() throws Exception {
        //Arrange
        UserDto userDto = UserDto.builder()
                .firstName("FirstName")
                .lastName("snjdgfjsdgnjksngjksdjfnsjadfnjsakfnjskdfbhsdfbhsdkfbhsdafhsadfhjsadbfhjsdf")
                .email("kate_thompson3@gmail.com")
                .password("password123")
                .isEmailConfirmed(false)
                .role(Role.ROLE_USER)
                .build();

        RequestBuilder requestBuilder = MockMvcRequestBuilders.post("/api/v1/auth/registration")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(userDto));

        //Act
        MvcResult result = this.mockMvc.perform(requestBuilder).andReturn();
        String string = result.getResponse().getContentAsString();
        ProblemDetail problemDetail = new ObjectMapper().readValue(string, ProblemDetail.class);
        int status = result.getResponse().getStatus();

        //Act
        assertEquals(400, status);
        assertEquals("Минимальная длина фамилии составляет 2 символа, максимальная - 30 символов", problemDetail.getDetail());
    }

    @Test
    public void registration_WhenUserDtoEmailIsBlank_ShouldThrowValidationException() throws Exception {
        //Arrange
        UserDto userDto = UserDto.builder()
                .firstName("FirstName")
                .lastName("Thompson")
                .email("kate_thompson3@gmail.com")
                .isEmailConfirmed(false)
                .role(Role.ROLE_USER)
                .build();

        RequestBuilder requestBuilder = MockMvcRequestBuilders.post("/api/v1/auth/registration")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(userDto));

        //Act
        MvcResult result = this.mockMvc.perform(requestBuilder).andReturn();
        String string = result.getResponse().getContentAsString();
        ProblemDetail problemDetail = new ObjectMapper().readValue(string, ProblemDetail.class);
        int status = result.getResponse().getStatus();

        //Act
        assertEquals(400, status);
        assertEquals("Ошибка валидации", problemDetail.getTitle());
    }

    @Test
    public void registration_WhenUserDtoEmailIsInvalid_ShouldThrowValidationException() throws Exception {
        //Arrange
        UserDto userDto = UserDto.builder()
                .firstName("FirsName")
                .lastName("Thompson")
                .email("invalidemailgmail.com")
                .password("password123")
                .isEmailConfirmed(false)
                .role(Role.ROLE_USER)
                .build();

        RequestBuilder requestBuilder = MockMvcRequestBuilders.post("/api/v1/auth/registration")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(userDto));

        //Act
        MvcResult result = this.mockMvc.perform(requestBuilder).andReturn();
        String string = result.getResponse().getContentAsString();
        ProblemDetail problemDetail = new ObjectMapper().readValue(string, ProblemDetail.class);
        int status = result.getResponse().getStatus();

        //Act
        assertEquals(400, status);
        assertEquals("Электронная почта должна быть валидной(иметь @)", problemDetail.getDetail());
    }

    @Test
    public void registration_WhenUserDtoEmailIsTooShort_ShouldThrowValidationException() throws Exception {
        //Arrange
        UserDto userDto = UserDto.builder()
                .firstName("FirstName")
                .lastName("Thompson")
                .email("@mai.ru")
                .password("password123")
                .isEmailConfirmed(false)
                .role(Role.ROLE_USER)
                .build();

        RequestBuilder requestBuilder = MockMvcRequestBuilders.post("/api/v1/auth/registration")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(userDto));

        //Act
        MvcResult result = this.mockMvc.perform(requestBuilder).andReturn();
        String string = result.getResponse().getContentAsString();
        ProblemDetail problemDetail = new ObjectMapper().readValue(string, ProblemDetail.class);
        int status = result.getResponse().getStatus();

        //Act
        assertEquals(400, status);
        assertTrue(problemDetail.getDetail().contains("Минимальная длина электронной почты составляет 8 символов, максимальная - 50 символов"));
    }

    @Test
    public void registration_WhenUserDtoEmailIsTooLong_ShouldThrowValidationException() throws Exception {
        //Arrange
        UserDto userDto = UserDto.builder()
                .firstName("FirstName")
                .lastName("Thompson")
                .email("kate_thompson843954773458y34857y4357823495y23y58235y2358y235y352y5fhdfh81883838838383838381jj3@gmail.com")
                .password("password123")
                .isEmailConfirmed(false)
                .role(Role.ROLE_USER)
                .build();

        RequestBuilder requestBuilder = MockMvcRequestBuilders.post("/api/v1/auth/registration")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(userDto));

        //Act
        MvcResult result = this.mockMvc.perform(requestBuilder).andReturn();
        String string = result.getResponse().getContentAsString();
        ProblemDetail problemDetail = new ObjectMapper().readValue(string, ProblemDetail.class);
        int status = result.getResponse().getStatus();

        //Act
        assertEquals(400, status);
        assertTrue(problemDetail.getDetail().contains("Минимальная длина электронной почты составляет 8 символов, максимальная - 50 символов"));
    }

    @Test
    public void registration_WhenUserDtoPasswordIsBlank_ShouldThrowValidationException() throws Exception {
        //Arrange
        UserDto userDto = UserDto.builder()
                .firstName("FirstName")
                .lastName("Thompson")
                .email("kate_thompson3@gmail.com")
                .password("")
                .isEmailConfirmed(false)
                .role(Role.ROLE_USER)
                .build();

        RequestBuilder requestBuilder = MockMvcRequestBuilders.post("/api/v1/auth/registration")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(userDto));

        //Act
        MvcResult result = this.mockMvc.perform(requestBuilder).andReturn();
        String string = result.getResponse().getContentAsString();
        ProblemDetail problemDetail = new ObjectMapper().readValue(string, ProblemDetail.class);
        int status = result.getResponse().getStatus();

        //Act
        assertEquals(400, status);
        assertEquals("Ошибка валидации", problemDetail.getTitle());
    }

    @Test
    public void registration_WhenUserDtoPasswordIsTooShort_ShouldThrowValidationException() throws Exception {
        //Arrange
        UserDto userDto = UserDto.builder()
                .firstName("FirstName")
                .lastName("Thompson")
                .email("kate_thompson3@gmail.com")
                .password("p")
                .isEmailConfirmed(false)
                .role(Role.ROLE_USER)
                .build();

        RequestBuilder requestBuilder = MockMvcRequestBuilders.post("/api/v1/auth/registration")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(userDto));

        //Act
        MvcResult result = this.mockMvc.perform(requestBuilder).andReturn();
        String string = result.getResponse().getContentAsString();
        ProblemDetail problemDetail = new ObjectMapper().readValue(string, ProblemDetail.class);
        int status = result.getResponse().getStatus();

        //Act
        assertEquals(400, status);
        assertEquals("Минимальная длина пароля составляет 8 символов, максимальная - 60 символов", problemDetail.getDetail());
    }

    @Test
    public void registration_WhenUserDtoPasswordIsTooLong_ShouldThrowValidationException() throws Exception {
        //Arrange
        UserDto userDto = UserDto.builder()
                .firstName("FistName")
                .lastName("Thompson")
                .email("kate_thompson3@gmail.com")
                .password("password123983284234723586258764573745310457963419564571374059634573405916345712312334343")
                .isEmailConfirmed(false)
                .role(Role.ROLE_USER)
                .build();

        RequestBuilder requestBuilder = MockMvcRequestBuilders.post("/api/v1/auth/registration")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(userDto));

        //Act
        MvcResult result = this.mockMvc.perform(requestBuilder).andReturn();
        String string = result.getResponse().getContentAsString();
        ProblemDetail problemDetail = new ObjectMapper().readValue(string, ProblemDetail.class);
        int status = result.getResponse().getStatus();

        //Act
        assertEquals(400, status);
        assertEquals("Минимальная длина пароля составляет 8 символов, максимальная - 60 символов", problemDetail.getDetail());
    }

    @Test
    public void registration_WhenUserDtoRoleIsNull_ShouldThrowValidationException() throws Exception {
        //Arrange
        UserDto userDto = UserDto.builder()
                .firstName("FirstName")
                .lastName("Thompson")
                .email("kate_thompson3@gmail.com")
                .password("password123")
                .isEmailConfirmed(false)
                .build();

        RequestBuilder requestBuilder = MockMvcRequestBuilders.post("/api/v1/auth/registration")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(userDto));

        //Act
        MvcResult result = this.mockMvc.perform(requestBuilder).andReturn();
        String string = result.getResponse().getContentAsString();
        ProblemDetail problemDetail = new ObjectMapper().readValue(string, ProblemDetail.class);
        int status = result.getResponse().getStatus();

        //Act
        assertEquals(400, status);
        assertEquals("Роль не может быть пустой", problemDetail.getDetail());
    }

    @Test
    public void login_WhenAuthRequestEmailIsBlank_ShouldThrowValidationException() throws Exception {
        //Arrange
        AuthRequest authRequest = new AuthRequest("", "password");

        RequestBuilder requestBuilder = MockMvcRequestBuilders.post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(authRequest));

        //Act
        MvcResult result = this.mockMvc.perform(requestBuilder).andReturn();
        String string = result.getResponse().getContentAsString();
        ProblemDetail problemDetail = new ObjectMapper().readValue(string, ProblemDetail.class);
        int status = result.getResponse().getStatus();

        //Act
        assertEquals(400, status);
        assertEquals("Ошибка валидации", problemDetail.getTitle());
    }

    @Test
    public void login_WhenAuthRequestEmailIsInvalid_ShouldThrowValidationException() throws Exception {
        //Arrange
        AuthRequest authRequest = new AuthRequest("emailgmail.com", "password");

        RequestBuilder requestBuilder = MockMvcRequestBuilders.post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(authRequest));

        //Act
        MvcResult result = this.mockMvc.perform(requestBuilder).andReturn();
        String string = result.getResponse().getContentAsString();
        ProblemDetail problemDetail = new ObjectMapper().readValue(string, ProblemDetail.class);
        int status = result.getResponse().getStatus();

        //Act
        assertEquals(400, status);
        assertEquals("Электронная почта должна быть валидной(иметь @)", problemDetail.getDetail());
    }

    @Test
    public void login_WhenAuthRequestEmailIsTooShort_ShouldThrowValidationException() throws Exception {
        //Arrange
        AuthRequest authRequest = new AuthRequest("@gil.cm", "password");

        RequestBuilder requestBuilder = MockMvcRequestBuilders.post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(authRequest));

        //Act
        MvcResult result = this.mockMvc.perform(requestBuilder).andReturn();
        String string = result.getResponse().getContentAsString();
        ProblemDetail problemDetail = new ObjectMapper().readValue(string, ProblemDetail.class);
        int status = result.getResponse().getStatus();

        //Act
        assertEquals(400, status);
        assertTrue(problemDetail.getDetail().contains("Минимальная длина электронной почты составляет 8 символов, максимальная - 50 символов"));
    }

    @Test
    public void login_WhenAuthRequestEmailIsTooLong_ShouldThrowValidationException() throws Exception {
        //Arrange
        AuthRequest authRequest = new AuthRequest("emaifgjkdfngjdfgndjfgnfgjnjsdfgnsdfgnjnjdfgkndsfngjdnfgjnjkdsfgnjkdfgnl@gmail.com", "password");

        RequestBuilder requestBuilder = MockMvcRequestBuilders.post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(authRequest));

        //Act
        MvcResult result = this.mockMvc.perform(requestBuilder).andReturn();
        String string = result.getResponse().getContentAsString();
        ProblemDetail problemDetail = new ObjectMapper().readValue(string, ProblemDetail.class);
        int status = result.getResponse().getStatus();

        //Act
        assertEquals(400, status);
        assertTrue(problemDetail.getDetail().contains("Минимальная длина электронной почты составляет 8 символов, максимальная - 50 символов"));
    }

    @Test
    public void login_WhenAuthRequestPasswordIsBlank_ShouldThrowValidationException() throws Exception {
        //Arrange
        AuthRequest authRequest = new AuthRequest("email@gmail.com", "");

        RequestBuilder requestBuilder = MockMvcRequestBuilders.post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(authRequest));

        //Act
        MvcResult result = this.mockMvc.perform(requestBuilder).andReturn();
        String string = result.getResponse().getContentAsString();
        ProblemDetail problemDetail = new ObjectMapper().readValue(string, ProblemDetail.class);
        int status = result.getResponse().getStatus();

        //Act
        assertEquals(400, status);
        assertEquals("Ошибка валидации", problemDetail.getTitle());
    }

    @Test
    public void login_WhenAuthRequestPasswordIsTooShort_ShouldThrowValidationException() throws Exception {
        //Arrange
        AuthRequest authRequest = new AuthRequest("email@gmail.com", "pa");

        RequestBuilder requestBuilder = MockMvcRequestBuilders.post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(authRequest));

        //Act
        MvcResult result = this.mockMvc.perform(requestBuilder).andReturn();
        String string = result.getResponse().getContentAsString();
        ProblemDetail problemDetail = new ObjectMapper().readValue(string, ProblemDetail.class);
        int status = result.getResponse().getStatus();

        //Act
        assertEquals(400, status);
        assertEquals("Минимальная длина пароля составляет 8 символов, максимальная - 60 символов", problemDetail.getDetail());
    }

    @Test
    public void login_WhenAuthRequestPasswordIsTooLong_ShouldThrowValidationException() throws Exception {
        //Arrange
        AuthRequest authRequest = new AuthRequest("email@gmail.com", "jfndfjsdnfhsbdfhsbdfsdfbsdfjbsdfjsfdhshdjfshdfhsdfbhsdfhjsdbfsbdhfbjhsdf");

        RequestBuilder requestBuilder = MockMvcRequestBuilders.post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(new ObjectMapper().writeValueAsString(authRequest));

        //Act
        MvcResult result = this.mockMvc.perform(requestBuilder).andReturn();
        String string = result.getResponse().getContentAsString();
        ProblemDetail problemDetail = new ObjectMapper().readValue(string, ProblemDetail.class);
        int status = result.getResponse().getStatus();

        //Act
        assertEquals(400, status);
        assertEquals("Минимальная длина пароля составляет 8 символов, максимальная - 60 символов", problemDetail.getDetail());
    }
}